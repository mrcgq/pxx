


//internal/socks5/server.go
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"phantom-x/internal/proto"
	"phantom-x/internal/stream"
	"phantom-x/internal/transport"
	"phantom-x/pkg/config"
	plog "phantom-x/pkg/log"
	"phantom-x/pkg/metrics"
)

// ==================== SOCKS5 常量 ====================

const (
	Version5       = 0x05
	AuthNone       = 0x00
	AuthUserPass   = 0x02
	AuthNoAccept   = 0xFF
	CmdConnect     = 0x01
	CmdBind        = 0x02
	CmdUDPAssoc    = 0x03
	AtypIPv4       = 0x01
	AtypDomain     = 0x03
	AtypIPv6       = 0x04
	RepSuccess     = 0x00
	RepServerFail  = 0x01
	RepNotAllowed  = 0x02
	RepNetUnreach  = 0x03
	RepHostUnreach = 0x04
	RepConnRefused = 0x05
	RepTTLExpired  = 0x06
	RepCmdNotSupp  = 0x07
	RepAtypNotSupp = 0x08
)

// 超时常量
const (
	HandshakeTimeout      = 10 * time.Second
	InitDataReadTimeout   = 20 * time.Millisecond
	RelayIdleTimeout      = 120 * time.Second
	UDPSessionIdleTimeout = 120 * time.Second
	UDPCleanupInterval    = 60 * time.Second
	DefaultMaxConnections = 10000
)

// ==================== 错误定义 ====================

var (
	ErrServerClosed     = errors.New("server closed")
	ErrTooManyConns     = errors.New("too many connections")
	ErrAuthFailed       = errors.New("authentication failed")
	ErrInvalidVersion   = errors.New("invalid SOCKS version")
	ErrInvalidCommand   = errors.New("invalid command")
	ErrInvalidAddrType  = errors.New("invalid address type")
	ErrConnectionClosed = errors.New("connection closed")
	ErrSessionNotFound  = errors.New("UDP session not found")
)

// ==================== 回调函数类型 ====================

type SendToFunc func(connID int, cmd byte, streamID uint32, payload []byte) error
type BroadcastFunc func(cmd byte, streamID uint32, payload []byte) error
type GetUplinkFunc func(streamID uint32) (connID int, ok bool)

// ==================== UDP 会话 ====================

type udpSession struct {
	streamID   uint32
	stream     *stream.Stream
	targetAddr string
	clientAddr *net.UDPAddr
	udpConn    *net.UDPConn
	opened     int32
	lastActive int64
	createTime time.Time
	mu         sync.RWMutex
}

func (s *udpSession) isOpened() bool {
	return atomic.LoadInt32(&s.opened) == 1
}

func (s *udpSession) setOpened() bool {
	return atomic.CompareAndSwapInt32(&s.opened, 0, 1)
}

func (s *udpSession) touch() {
	atomic.StoreInt64(&s.lastActive, time.Now().Unix())
}

func (s *udpSession) isExpired(timeout time.Duration) bool {
	lastActive := time.Unix(atomic.LoadInt64(&s.lastActive), 0)
	return time.Since(lastActive) > timeout
}

func (s *udpSession) setClientAddr(addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientAddr = addr
}

func (s *udpSession) getClientAddr() *net.UDPAddr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientAddr
}

func (s *udpSession) setUDPConn(conn *net.UDPConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.udpConn = conn
}

func (s *udpSession) getUDPConn() *net.UDPConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.udpConn
}

// ==================== UDP 会话管理器 ====================

type udpSessionManager struct {
	sessions   map[string]*udpSession
	byStreamID map[uint32]*udpSession
	mu         sync.RWMutex
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

func newUDPSessionManager() *udpSessionManager {
	m := &udpSessionManager{
		sessions:   make(map[string]*udpSession),
		byStreamID: make(map[uint32]*udpSession),
		stopCh:     make(chan struct{}),
	}
	return m
}

func (m *udpSessionManager) start() {
	m.wg.Add(1)
	go m.cleanupLoop()
}

func (m *udpSessionManager) stop() {
	close(m.stopCh)
	m.wg.Wait()
}

func (m *udpSessionManager) makeKey(clientAddr, target string) string {
	return clientAddr + "|" + target
}

func (m *udpSessionManager) getOrCreate(clientAddr *net.UDPAddr, target string, streamIDGen func() uint32, udpConn *net.UDPConn) (*udpSession, bool) {
	clientKey := clientAddr.String()
	key := m.makeKey(clientKey, target)

	m.mu.RLock()
	if session, ok := m.sessions[key]; ok {
		session.touch()
		m.mu.RUnlock()
		return session, false
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	if session, ok := m.sessions[key]; ok {
		session.touch()
		return session, false
	}

	streamID := streamIDGen()
	session := &udpSession{
		streamID:   streamID,
		targetAddr: target,
		clientAddr: clientAddr,
		udpConn:    udpConn,
		lastActive: time.Now().Unix(),
		createTime: time.Now(),
	}
	m.sessions[key] = session
	m.byStreamID[streamID] = session
	return session, true
}

func (m *udpSessionManager) getByStreamID(streamID uint32) *udpSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byStreamID[streamID]
}

func (m *udpSessionManager) removeByStreamID(streamID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, ok := m.byStreamID[streamID]; ok {
		clientKey := ""
		if session.clientAddr != nil {
			clientKey = session.clientAddr.String()
		}
		key := m.makeKey(clientKey, session.targetAddr)
		delete(m.sessions, key)
		delete(m.byStreamID, streamID)
	}
}

func (m *udpSessionManager) cleanupLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(UDPCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

func (m *udpSessionManager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, session := range m.sessions {
		if session.isExpired(UDPSessionIdleTimeout) {
			delete(m.byStreamID, session.streamID)
			delete(m.sessions, key)
			plog.Debug("[SOCKS5] Cleaned up expired UDP session: %s (streamID=%d)", key, session.streamID)
		}
	}
}

func (m *udpSessionManager) closeAll(broadcastFunc BroadcastFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, session := range m.sessions {
		if broadcastFunc != nil && session.isOpened() {
			_ = broadcastFunc(proto.CmdClose, session.streamID, nil)
		}
	}
	m.sessions = make(map[string]*udpSession)
	m.byStreamID = make(map[uint32]*udpSession)
}

func (m *udpSessionManager) count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// ==================== 服务器统计 ====================

type ServerStats struct {
	ActiveConnections int64
	TotalConnections  int64
	ActiveUDPSessions int
	TotalRequests     int64
	FailedRequests    int64
}

// ==================== SOCKS5 服务器 ====================

type Server struct {
	cfg       *config.ClientConfig
	listener  net.Listener
	streamMgr *stream.Manager

	username string
	password string

	sendToFunc    SendToFunc
	broadcastFunc BroadcastFunc
	getUplinkFunc GetUplinkFunc

	udpSessions *udpSessionManager

	ipStrategy byte

	maxConnections int64
	activeConns    int64

	totalConns     int64
	totalRequests  int64
	failedRequests int64

	ctx      context.Context
	cancel   context.CancelFunc
	stopOnce sync.Once
	wg       sync.WaitGroup
	stopped  int32
}

func NewServer(cfg *config.ClientConfig, mgr *stream.Manager) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		cfg:            cfg,
		streamMgr:      mgr,
		ipStrategy:     parseIPStrategy(cfg.IPStrategy),
		maxConnections: DefaultMaxConnections,
		udpSessions:    newUDPSessionManager(),
		ctx:            ctx,
		cancel:         cancel,
	}

	if cfg.Socks5Auth != "" {
		parts := strings.SplitN(cfg.Socks5Auth, ":", 2)
		if len(parts) == 2 {
			s.username = parts[0]
			s.password = parts[1]
		}
	}

	return s
}

func (s *Server) SetSendToFunc(f SendToFunc) {
	s.sendToFunc = f
}

func (s *Server) SetBroadcastFunc(f BroadcastFunc) {
	s.broadcastFunc = f
}

func (s *Server) SetGetUplinkFunc(f GetUplinkFunc) {
	s.getUplinkFunc = f
}

func (s *Server) SetMaxConnections(max int64) {
	atomic.StoreInt64(&s.maxConnections, max)
}

func (s *Server) Stats() ServerStats {
	return ServerStats{
		ActiveConnections: atomic.LoadInt64(&s.activeConns),
		TotalConnections:  atomic.LoadInt64(&s.totalConns),
		ActiveUDPSessions: s.udpSessions.count(),
		TotalRequests:     atomic.LoadInt64(&s.totalRequests),
		FailedRequests:    atomic.LoadInt64(&s.failedRequests),
	}
}

func (s *Server) Start() error {
	addr := s.cfg.Socks5Listen
	if addr == "" {
		addr = ":1080"
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}
	s.listener = listener

	s.udpSessions.start()

	s.wg.Add(1)
	go s.acceptLoop()

	plog.Info("[SOCKS5] Listening on %s", addr)
	return nil
}

func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		atomic.StoreInt32(&s.stopped, 1)
		s.cancel()

		if s.listener != nil {
			_ = s.listener.Close()
		}

		s.udpSessions.stop()
		s.udpSessions.closeAll(s.broadcastFunc)

		s.wg.Wait()

		plog.Info("[SOCKS5] Server stopped")
	})
}

func (s *Server) IsStopped() bool {
	return atomic.LoadInt32(&s.stopped) == 1
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				if !isClosedError(err) {
					plog.Debug("[SOCKS5] Accept error: %v", err)
				}
				continue
			}
		}

		if !s.acquireConnection() {
			_ = conn.Close()
			plog.Debug("[SOCKS5] Connection limit reached, rejecting")
			continue
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				s.releaseConnection()
				s.wg.Done()
			}()
			s.handleConnection(c)
		}(conn)
	}
}

func (s *Server) acquireConnection() bool {
	for {
		current := atomic.LoadInt64(&s.activeConns)
		max := atomic.LoadInt64(&s.maxConnections)
		if current >= max {
			return false
		}
		if atomic.CompareAndSwapInt64(&s.activeConns, current, current+1) {
			atomic.AddInt64(&s.totalConns, 1)
			return true
		}
	}
}

func (s *Server) releaseConnection() {
	atomic.AddInt64(&s.activeConns, -1)
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	if err := conn.SetDeadline(time.Now().Add(HandshakeTimeout)); err != nil {
		return
	}

	if err := s.handshake(conn); err != nil {
		plog.Debug("[SOCKS5] Handshake failed: %v", err)
		atomic.AddInt64(&s.failedRequests, 1)
		return
	}

	cmd, atyp, addr, port, err := s.readRequest(conn)
	if err != nil {
		plog.Debug("[SOCKS5] Read request failed: %v", err)
		atomic.AddInt64(&s.failedRequests, 1)
		return
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}

	atomic.AddInt64(&s.totalRequests, 1)

	target := proto.FormatHostPort(addr, port)

	switch cmd {
	case CmdConnect:
		s.handleConnect(conn, target, addr, port, atyp)
	case CmdUDPAssoc:
		s.handleUDPAssociate(conn)
	default:
		s.sendReply(conn, RepCmdNotSupp, nil)
		atomic.AddInt64(&s.failedRequests, 1)
	}
}

func (s *Server) handshake(conn net.Conn) error {
	buf := make([]byte, 256)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}
	if buf[0] != Version5 {
		return ErrInvalidVersion
	}

	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return err
	}

	if s.username != "" {
		hasUserPass := false
		for i := 0; i < nmethods; i++ {
			if buf[i] == AuthUserPass {
				hasUserPass = true
				break
			}
		}
		if !hasUserPass {
			_, _ = conn.Write([]byte{Version5, AuthNoAccept})
			return ErrAuthFailed
		}
		_, _ = conn.Write([]byte{Version5, AuthUserPass})
		return s.authenticateUserPass(conn)
	}

	_, _ = conn.Write([]byte{Version5, AuthNone})
	return nil
}

func (s *Server) authenticateUserPass(conn net.Conn) error {
	buf := make([]byte, 256)

	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return err
	}
	if buf[0] != 0x01 {
		return errors.New("invalid auth version")
	}

	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return err
	}
	ulen := int(buf[0])
	if ulen > 255 {
		return errors.New("username too long")
	}
	if _, err := io.ReadFull(conn, buf[:ulen]); err != nil {
		return err
	}
	username := string(buf[:ulen])

	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return err
	}
	plen := int(buf[0])
	if plen > 255 {
		return errors.New("password too long")
	}
	if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
		return err
	}
	password := string(buf[:plen])

	if username == s.username && password == s.password {
		_, _ = conn.Write([]byte{0x01, 0x00})
		return nil
	}

	_, _ = conn.Write([]byte{0x01, 0x01})
	return ErrAuthFailed
}

func (s *Server) readRequest(conn net.Conn) (cmd, atyp byte, addr string, port uint16, err error) {
	buf := make([]byte, 256)

	if _, err = io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != Version5 {
		err = ErrInvalidVersion
		return
	}

	cmd = buf[1]
	atyp = buf[3]

	switch atyp {
	case AtypIPv4:
		if _, err = io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		addr = net.IP(buf[:4]).String()

	case AtypDomain:
		if _, err = io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if domainLen == 0 || domainLen > 253 {
			err = errors.New("invalid domain length")
			return
		}
		if _, err = io.ReadFull(conn, buf[:domainLen]); err != nil {
			return
		}
		addr = string(buf[:domainLen])

		if verr := proto.ValidateHost(addr); verr != nil {
			err = verr
			return
		}

	case AtypIPv6:
		if _, err = io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		addr = net.IP(buf[:16]).String()

	default:
		err = ErrInvalidAddrType
		return
	}

	if _, err = io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(buf[:2])

	return
}

func (s *Server) sendReply(conn net.Conn, rep byte, bindAddr net.Addr) {
	reply := []byte{Version5, rep, 0x00, AtypIPv4, 0, 0, 0, 0, 0, 0}

	if bindAddr != nil {
		if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok {
			if ip4 := tcpAddr.IP.To4(); ip4 != nil {
				reply[3] = AtypIPv4
				copy(reply[4:8], ip4)
				reply[8] = byte(tcpAddr.Port >> 8)
				reply[9] = byte(tcpAddr.Port)
			} else if ip6 := tcpAddr.IP.To16(); ip6 != nil {
				reply = make([]byte, 22)
				reply[0] = Version5
				reply[1] = rep
				reply[2] = 0x00
				reply[3] = AtypIPv6
				copy(reply[4:20], ip6)
				reply[20] = byte(tcpAddr.Port >> 8)
				reply[21] = byte(tcpAddr.Port)
			}
		}
	}

	_, _ = conn.Write(reply)
}

func (s *Server) handleConnect(conn net.Conn, target, host string, port uint16, atyp byte) {
	if !s.checkIPStrategy(host, atyp) {
		s.sendReply(conn, RepNotAllowed, nil)
		atomic.AddInt64(&s.failedRequests, 1)
		return
	}

	s.sendReply(conn, RepSuccess, nil)

	if err := conn.SetReadDeadline(time.Now().Add(InitDataReadTimeout)); err != nil {
		return
	}
	initBuf := make([]byte, proto.MaxInitData)
	n, _ := conn.Read(initBuf)
	_ = conn.SetReadDeadline(time.Time{})
	initData := initBuf[:n]

	streamID := s.streamMgr.NewStreamID()
	st := stream.NewStream(streamID, target, false)
	st.SetState(stream.StateConnecting)
	s.streamMgr.Register(st)

	payload := proto.BuildOpenPayload(s.ipStrategy, host, port, initData)

	if s.broadcastFunc != nil {
		if err := s.broadcastFunc(proto.CmdOpenTCP, streamID, payload); err != nil {
			plog.Warn("[SOCKS5] Failed to send open command: %v", err)
			s.streamMgr.Unregister(streamID)
			atomic.AddInt64(&s.failedRequests, 1)
			return
		}
	}

	plog.Debug("[SOCKS5] CONNECT %s (InitData: %d bytes)", target, len(initData))

	s.relay(conn, st)
}

func (s *Server) relay(conn net.Conn, st *stream.Stream) {
	var wg sync.WaitGroup

	defer func() {
		st.Close()
		wg.Wait()

		if s.getUplinkFunc != nil {
			if connID, ok := s.getUplinkFunc(st.ID); ok && s.sendToFunc != nil {
				_ = s.sendToFunc(connID, proto.CmdClose, st.ID, nil)
			} else if s.broadcastFunc != nil {
				_ = s.broadcastFunc(proto.CmdClose, st.ID, nil)
			}
		} else if s.broadcastFunc != nil {
			_ = s.broadcastFunc(proto.CmdClose, st.ID, nil)
		}

		_ = conn.Close()
		s.streamMgr.Unregister(st.ID)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		bufPtr := transport.GetBuffer(32 * 1024)
		buf := *bufPtr
		defer transport.PutBuffer(bufPtr)

		for {
			select {
			case <-st.CloseCh:
				return
			case <-s.ctx.Done():
				return
			default:
			}

			if err := conn.SetReadDeadline(time.Now().Add(RelayIdleTimeout)); err != nil {
				return
			}
			nr, err := conn.Read(buf)
			if err != nil {
				return
			}

			if nr > 0 {
				data := make([]byte, nr)
				copy(data, buf[:nr])

				connID := st.GetConnID()
				if connID >= 0 && s.sendToFunc != nil {
					_ = s.sendToFunc(connID, proto.CmdData, st.ID, data)
				} else if s.broadcastFunc != nil {
					_ = s.broadcastFunc(proto.CmdData, st.ID, data)
				}

				metrics.AddBytesSent(int64(nr))
			}
		}
	}()

	for {
		select {
		case data, ok := <-st.DataCh:
			if !ok {
				return
			}
			if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return
			}
			if _, err := conn.Write(data); err != nil {
				return
			}
			metrics.AddBytesRecv(int64(len(data)))

		case <-st.CloseCh:
			return

		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Server) handleUDPAssociate(conn net.Conn) {
	localIP := conn.LocalAddr().(*net.TCPAddr).IP
	udpAddr := &net.UDPAddr{IP: localIP, Port: 0}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.sendReply(conn, RepServerFail, nil)
		atomic.AddInt64(&s.failedRequests, 1)
		return
	}

	actualAddr := udpListener.LocalAddr().(*net.UDPAddr)
	s.sendReply(conn, RepSuccess, &net.TCPAddr{IP: actualAddr.IP, Port: actualAddr.Port})

	plog.Debug("[SOCKS5] UDP ASSOCIATE on %s", actualAddr)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.handleUDPRelay(udpListener)
	}()

	buf := make([]byte, 1)
	for {
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}

	_ = udpListener.Close()
	wg.Wait()
}

func (s *Server) handleUDPRelay(udpListener *net.UDPConn) {
	bufPtr := transport.GetBuffer(64 * 1024)
	buf := *bufPtr
	defer transport.PutBuffer(bufPtr)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		if err := udpListener.SetReadDeadline(time.Now().Add(UDPSessionIdleTimeout)); err != nil {
			return
		}
		n, clientAddr, err := udpListener.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		target, data, err := ParseUDPPacket(buf[:n])
		if err != nil {
			plog.Debug("[SOCKS5] Invalid UDP packet: %v", err)
			continue
		}

		session, isNew := s.udpSessions.getOrCreate(clientAddr, target, s.streamMgr.NewStreamID, udpListener)

		if isNew {
			plog.Debug("[SOCKS5] New UDP session: %s -> %s (streamID=%d)", clientAddr, target, session.streamID)

			st := stream.NewStream(session.streamID, target, true)
			st.SetState(stream.StateConnecting)
			st.UDPConn = udpListener
			st.UDPClientAddr = clientAddr
			session.stream = st
			s.streamMgr.Register(st)
		}

		session.touch()
		session.setClientAddr(clientAddr)
		session.setUDPConn(udpListener)

		if session.setOpened() {
			host, port, err := proto.ParseHostPort(target)
			if err != nil {
				plog.Debug("[SOCKS5] Invalid target: %s", target)
				continue
			}

			openPayload := proto.BuildOpenPayload(s.ipStrategy, host, port, nil)
			if s.broadcastFunc != nil {
				if err := s.broadcastFunc(proto.CmdOpenUDP, session.streamID, openPayload); err != nil {
					plog.Warn("[SOCKS5] Failed to send UDP open command: %v", err)
					continue
				}
			}

			if session.stream != nil {
				session.stream.SetState(stream.StateConnected)
			}
		}

		if s.broadcastFunc != nil {
			if err := s.broadcastFunc(proto.CmdData, session.streamID, data); err != nil {
				plog.Debug("[SOCKS5] Failed to send UDP data: %v", err)
			} else {
				metrics.AddBytesSent(int64(len(data)))
			}
		}
	}
}

func (s *Server) HandleUDPResponse(streamID uint32, data []byte) error {
	session := s.udpSessions.getByStreamID(streamID)
	if session == nil {
		return ErrSessionNotFound
	}

	clientAddr := session.getClientAddr()
	udpConn := session.getUDPConn()

	if clientAddr == nil || udpConn == nil {
		return errors.New("UDP session not ready")
	}

	host, port, err := proto.ParseHostPort(session.targetAddr)
	if err != nil {
		return err
	}

	responsePacket := BuildUDPPacket(host, port, data)

	_, err = udpConn.WriteToUDP(responsePacket, clientAddr)
	if err != nil {
		plog.Debug("[SOCKS5] Failed to send UDP response to client: %v", err)
		return err
	}

	session.touch()
	metrics.AddBytesRecv(int64(len(data)))

	return nil
}

func (s *Server) HandleUDPClose(streamID uint32) {
	session := s.udpSessions.getByStreamID(streamID)
	if session != nil {
		s.streamMgr.Unregister(streamID)
		s.udpSessions.removeByStreamID(streamID)
		plog.Debug("[SOCKS5] UDP session closed: streamID=%d", streamID)
	}
}

func (s *Server) checkIPStrategy(host string, atyp byte) bool {
	ip := net.ParseIP(host)

	switch s.ipStrategy {
	case proto.IPv4Only:
		if atyp == AtypIPv6 || (ip != nil && ip.To4() == nil) {
			return false
		}
	case proto.IPv6Only:
		if atyp == AtypIPv4 || (ip != nil && ip.To4() != nil) {
			return false
		}
	}
	return true
}

// ==================== 辅助函数 ====================

func parseIPStrategy(s string) byte {
	s = strings.TrimSpace(s)
	switch s {
	case "4":
		return proto.IPv4Only
	case "6":
		return proto.IPv6Only
	case "4,6":
		return proto.IPv4First
	case "6,4":
		return proto.IPv6First
	default:
		return proto.IPDefault
	}
}

func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

// ==================== UDP 包解析 ====================

func ParseUDPPacket(b []byte) (target string, data []byte, err error) {
	if len(b) < 10 {
		return "", nil, errors.New("packet too short")
	}

	if b[2] != 0 {
		return "", nil, errors.New("fragmentation not supported")
	}

	off := 4
	var host string

	switch b[3] {
	case AtypIPv4:
		if off+4 > len(b) {
			return "", nil, errors.New("too short for IPv4")
		}
		host = net.IP(b[off : off+4]).String()
		off += 4

	case AtypDomain:
		if off+1 > len(b) {
			return "", nil, errors.New("too short for domain length")
		}
		domainLen := int(b[off])
		off++
		if off+domainLen > len(b) {
			return "", nil, errors.New("too short for domain")
		}
		host = string(b[off : off+domainLen])
		off += domainLen

	case AtypIPv6:
		if off+16 > len(b) {
			return "", nil, errors.New("too short for IPv6")
		}
		host = net.IP(b[off : off+16]).String()
		off += 16

	default:
		return "", nil, errors.New("invalid address type")
	}

	if off+2 > len(b) {
		return "", nil, errors.New("too short for port")
	}

	port := binary.BigEndian.Uint16(b[off : off+2])
	off += 2

	target = proto.FormatHostPort(host, port)
	data = b[off:]

	return
}

func BuildUDPPacket(host string, port uint16, data []byte) []byte {
	buf := []byte{0, 0, 0}

	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, AtypIPv4)
		buf = append(buf, ip4...)
	} else if ip != nil {
		buf = append(buf, AtypIPv6)
		buf = append(buf, ip.To16()...)
	} else {
		buf = append(buf, AtypDomain, byte(len(host)))
		buf = append(buf, host...)
	}

	buf = append(buf, byte(port>>8), byte(port))
	buf = append(buf, data...)

	return buf
}









