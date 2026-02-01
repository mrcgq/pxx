
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
	stream     *stream.Stream  // 关联的流
	targetAddr string
	clientAddr *net.UDPAddr    // 客户端 UDP 地址
	udpConn    *net.UDPConn    // 关联的 UDP 连接（用于发送响应）
	opened     int32           // 原子操作
	lastActive int64           // Unix timestamp，原子操作
	createTime time.Time
	mu         sync.RWMutex
}

// isOpened 检查会话是否已打开
func (s *udpSession) isOpened() bool {
	return atomic.LoadInt32(&s.opened) == 1
}

// setOpened 设置会话为已打开
func (s *udpSession) setOpened() bool {
	return atomic.CompareAndSwapInt32(&s.opened, 0, 1)
}

// touch 更新最后活动时间
func (s *udpSession) touch() {
	atomic.StoreInt64(&s.lastActive, time.Now().Unix())
}

// isExpired 检查会话是否过期
func (s *udpSession) isExpired(timeout time.Duration) bool {
	lastActive := time.Unix(atomic.LoadInt64(&s.lastActive), 0)
	return time.Since(lastActive) > timeout
}

// setClientAddr 设置客户端地址
func (s *udpSession) setClientAddr(addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientAddr = addr
}

// getClientAddr 获取客户端地址
func (s *udpSession) getClientAddr() *net.UDPAddr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientAddr
}

// setUDPConn 设置 UDP 连接
func (s *udpSession) setUDPConn(conn *net.UDPConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.udpConn = conn
}

// getUDPConn 获取 UDP 连接
func (s *udpSession) getUDPConn() *net.UDPConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.udpConn
}

// ==================== UDP 会话管理器 ====================

type udpSessionManager struct {
	sessions     map[string]*udpSession   // key: clientAddr + "|" + target
	byStreamID   map[uint32]*udpSession   // 通过 streamID 查找会话
	mu           sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

func newUDPSessionManager() *udpSessionManager {
	m := &udpSessionManager{
		sessions:   make(map[string]*udpSession),
		byStreamID: make(map[uint32]*udpSession),
		stopCh:     make(chan struct{}),
	}
	return m
}

// start 启动清理协程
func (m *udpSessionManager) start() {
	m.wg.Add(1)
	go m.cleanupLoop()
}

// stop 停止管理器
func (m *udpSessionManager) stop() {
	close(m.stopCh)
	m.wg.Wait()
}

// makeKey 生成会话 key（包含客户端地址以隔离不同客户端）
func (m *udpSessionManager) makeKey(clientAddr, target string) string {
	return clientAddr + "|" + target
}

// getOrCreate 获取或创建会话
func (m *udpSessionManager) getOrCreate(clientAddr *net.UDPAddr, target string, streamIDGen func() uint32, udpConn *net.UDPConn) (*udpSession, bool) {
	clientKey := clientAddr.String()
	key := m.makeKey(clientKey, target)

	// 快速路径：读锁检查
	m.mu.RLock()
	if session, ok := m.sessions[key]; ok {
		session.touch()
		m.mu.RUnlock()
		return session, false
	}
	m.mu.RUnlock()

	// 慢速路径：写锁创建
	m.mu.Lock()
	defer m.mu.Unlock()

	// 双重检查
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

// get 获取会话
func (m *udpSessionManager) get(clientAddr, target string) *udpSession {
	key := m.makeKey(clientAddr, target)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[key]
}

// getByStreamID 通过 streamID 获取会话
func (m *udpSessionManager) getByStreamID(streamID uint32) *udpSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byStreamID[streamID]
}

// remove 删除会话
func (m *udpSessionManager) remove(clientAddr, target string) {
	key := m.makeKey(clientAddr, target)
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if session, ok := m.sessions[key]; ok {
		delete(m.byStreamID, session.streamID)
		delete(m.sessions, key)
	}
}

// removeByStreamID 通过 streamID 删除会话
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

// cleanupLoop 清理过期会话
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

// cleanup 清理过期会话
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

// closeAll 关闭所有会话
func (m *udpSessionManager) closeAll(broadcastFunc BroadcastFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, session := range m.sessions {
		if broadcastFunc != nil && session.isOpened() {
			broadcastFunc(proto.CmdClose, session.streamID, nil)
		}
	}
	m.sessions = make(map[string]*udpSession)
	m.byStreamID = make(map[uint32]*udpSession)
}

// count 返回会话数量
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

	// 认证
	username string
	password string

	// 回调函数
	sendToFunc    SendToFunc
	broadcastFunc BroadcastFunc
	getUplinkFunc GetUplinkFunc

	// UDP 会话管理
	udpSessions *udpSessionManager

	// IP 策略
	ipStrategy byte

	// 连接限制
	maxConnections int64
	activeConns    int64

	// 统计
	totalConns     int64
	totalRequests  int64
	failedRequests int64

	// 生命周期控制
	ctx      context.Context
	cancel   context.CancelFunc
	stopOnce sync.Once
	wg       sync.WaitGroup
	stopped  int32
}

// NewServer 创建 SOCKS5 服务器
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

	// 解析认证信息
	if cfg.Socks5Auth != "" {
		parts := strings.SplitN(cfg.Socks5Auth, ":", 2)
		if len(parts) == 2 {
			s.username = parts[0]
			s.password = parts[1]
		}
	}

	return s
}

// SetSendToFunc 设置发送到指定连接的回调
func (s *Server) SetSendToFunc(f SendToFunc) {
	s.sendToFunc = f
}

// SetBroadcastFunc 设置广播回调
func (s *Server) SetBroadcastFunc(f BroadcastFunc) {
	s.broadcastFunc = f
}

// SetGetUplinkFunc 设置获取上行连接的回调
func (s *Server) SetGetUplinkFunc(f GetUplinkFunc) {
	s.getUplinkFunc = f
}

// SetMaxConnections 设置最大连接数
func (s *Server) SetMaxConnections(max int64) {
	atomic.StoreInt64(&s.maxConnections, max)
}

// Stats 返回服务器统计信息
func (s *Server) Stats() ServerStats {
	return ServerStats{
		ActiveConnections: atomic.LoadInt64(&s.activeConns),
		TotalConnections:  atomic.LoadInt64(&s.totalConns),
		ActiveUDPSessions: s.udpSessions.count(),
		TotalRequests:     atomic.LoadInt64(&s.totalRequests),
		FailedRequests:    atomic.LoadInt64(&s.failedRequests),
	}
}

// Start 启动服务器
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

	// 启动 UDP 会话管理器
	s.udpSessions.start()

	// 启动接受连接循环
	s.wg.Add(1)
	go s.acceptLoop()

	plog.Info("[SOCKS5] Listening on %s", addr)
	return nil
}

// Stop 停止服务器
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		atomic.StoreInt32(&s.stopped, 1)
		s.cancel()

		if s.listener != nil {
			s.listener.Close()
		}

		// 停止 UDP 会话管理器
		s.udpSessions.stop()

		// 关闭所有 UDP 会话
		s.udpSessions.closeAll(s.broadcastFunc)

		// 等待所有 goroutine 完成
		s.wg.Wait()

		plog.Info("[SOCKS5] Server stopped")
	})
}

// IsStopped 检查服务器是否已停止
func (s *Server) IsStopped() bool {
	return atomic.LoadInt32(&s.stopped) == 1
}

// acceptLoop 接受连接循环
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

		// 检查连接限制
		if !s.acquireConnection() {
			conn.Close()
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

// acquireConnection 获取连接槽位
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

// releaseConnection 释放连接槽位
func (s *Server) releaseConnection() {
	atomic.AddInt64(&s.activeConns, -1)
}

// handleConnection 处理单个连接
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// 设置握手超时
	conn.SetDeadline(time.Now().Add(HandshakeTimeout))

	// SOCKS5 握手
	if err := s.handshake(conn); err != nil {
		plog.Debug("[SOCKS5] Handshake failed: %v", err)
		atomic.AddInt64(&s.failedRequests, 1)
		return
	}

	// 读取请求
	cmd, atyp, addr, port, err := s.readRequest(conn)
	if err != nil {
		plog.Debug("[SOCKS5] Read request failed: %v", err)
		atomic.AddInt64(&s.failedRequests, 1)
		return
	}

	// 清除超时
	conn.SetDeadline(time.Time{})

	atomic.AddInt64(&s.totalRequests, 1)

	// 使用正确的 IPv6 格式化
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

// handshake 执行 SOCKS5 握手
func (s *Server) handshake(conn net.Conn) error {
	buf := make([]byte, 256)

	// 读取版本和方法数量
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}
	if buf[0] != Version5 {
		return ErrInvalidVersion
	}

	// 读取支持的方法
	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return err
	}

	// 选择认证方法
	if s.username != "" {
		// 需要用户名密码认证
		hasUserPass := false
		for i := 0; i < nmethods; i++ {
			if buf[i] == AuthUserPass {
				hasUserPass = true
				break
			}
		}
		if !hasUserPass {
			conn.Write([]byte{Version5, AuthNoAccept})
			return ErrAuthFailed
		}
		conn.Write([]byte{Version5, AuthUserPass})
		return s.authenticateUserPass(conn)
	}

	// 无需认证
	conn.Write([]byte{Version5, AuthNone})
	return nil
}

// authenticateUserPass 用户名密码认证
func (s *Server) authenticateUserPass(conn net.Conn) error {
	buf := make([]byte, 256)

	// 读取认证版本
	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return err
	}
	if buf[0] != 0x01 {
		return errors.New("invalid auth version")
	}

	// 读取用户名
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

	// 读取密码
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

	// 验证
	if username == s.username && password == s.password {
		conn.Write([]byte{0x01, 0x00})
		return nil
	}

	conn.Write([]byte{0x01, 0x01})
	return ErrAuthFailed
}

// readRequest 读取 SOCKS5 请求
func (s *Server) readRequest(conn net.Conn) (cmd, atyp byte, addr string, port uint16, err error) {
	buf := make([]byte, 256)

	// 读取请求头
	if _, err = io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != Version5 {
		err = ErrInvalidVersion
		return
	}

	cmd = buf[1]
	// buf[2] 是保留字段
	atyp = buf[3]

	// 读取地址
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

		// 验证域名
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

	// 读取端口
	if _, err = io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(buf[:2])

	return
}

// sendReply 发送 SOCKS5 响应
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
				// IPv6 响应
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

	conn.Write(reply)
}

// handleConnect 处理 CONNECT 命令
func (s *Server) handleConnect(conn net.Conn, target, host string, port uint16, atyp byte) {
	// 检查 IP 策略
	if !s.checkIPStrategy(host, atyp) {
		s.sendReply(conn, RepNotAllowed, nil)
		atomic.AddInt64(&s.failedRequests, 1)
		return
	}

	// 发送成功响应（0-RTT：先响应再建立连接）
	s.sendReply(conn, RepSuccess, nil)

	// 尝试读取初始数据（0-RTT）
	conn.SetReadDeadline(time.Now().Add(InitDataReadTimeout))
	initBuf := make([]byte, proto.MaxInitData)
	n, _ := conn.Read(initBuf)
	conn.SetReadDeadline(time.Time{})
	initData := initBuf[:n]

	// 创建流
	streamID := s.streamMgr.NewStreamID()
	st := stream.NewStream(streamID, target, false)
	st.SetState(stream.StateConnecting)
	s.streamMgr.Register(st)

	// 构建 Open 命令
	payload := proto.BuildOpenPayload(s.ipStrategy, host, port, initData)

	// 发送 Open 命令
	if s.broadcastFunc != nil {
		if err := s.broadcastFunc(proto.CmdOpenTCP, streamID, payload); err != nil {
			plog.Warn("[SOCKS5] Failed to send open command: %v", err)
			s.streamMgr.Unregister(streamID)
			atomic.AddInt64(&s.failedRequests, 1)
			return
		}
	}

	plog.Debug("[SOCKS5] CONNECT %s (InitData: %d bytes)", target, len(initData))

	// 开始数据转发
	s.relay(conn, st)
}

// relay 数据转发
func (s *Server) relay(conn net.Conn, st *stream.Stream) {
	var wg sync.WaitGroup

	defer func() {
		st.Close()
		wg.Wait()

		// 发送关闭命令
		if s.getUplinkFunc != nil {
			if connID, ok := s.getUplinkFunc(st.ID); ok && s.sendToFunc != nil {
				s.sendToFunc(connID, proto.CmdClose, st.ID, nil)
			} else if s.broadcastFunc != nil {
				s.broadcastFunc(proto.CmdClose, st.ID, nil)
			}
		} else if s.broadcastFunc != nil {
			s.broadcastFunc(proto.CmdClose, st.ID, nil)
		}

		conn.Close()
		s.streamMgr.Unregister(st.ID)
	}()

	// 从本地连接读取数据发送到远程
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

			conn.SetReadDeadline(time.Now().Add(RelayIdleTimeout))
			nr, err := conn.Read(buf)
			if err != nil {
				return
			}

			if nr > 0 {
				data := make([]byte, nr)
				copy(data, buf[:nr])

				// 发送数据
				connID := st.GetConnID()
				if connID >= 0 && s.sendToFunc != nil {
					s.sendToFunc(connID, proto.CmdData, st.ID, data)
				} else if s.broadcastFunc != nil {
					s.broadcastFunc(proto.CmdData, st.ID, data)
				}

				metrics.AddBytesSent(int64(nr))
			}
		}
	}()

	// 从远程接收数据写入本地连接
	for {
		select {
		case data, ok := <-st.DataCh:
			if !ok {
				return
			}
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
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

// handleUDPAssociate 处理 UDP ASSOCIATE 命令
func (s *Server) handleUDPAssociate(conn net.Conn) {
	// 创建 UDP 监听器
	localIP := conn.LocalAddr().(*net.TCPAddr).IP
	udpAddr := &net.UDPAddr{IP: localIP, Port: 0}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.sendReply(conn, RepServerFail, nil)
		atomic.AddInt64(&s.failedRequests, 1)
		return
	}

	// 发送成功响应，告知客户端 UDP 端口
	actualAddr := udpListener.LocalAddr().(*net.UDPAddr)
	s.sendReply(conn, RepSuccess, &net.TCPAddr{IP: actualAddr.IP, Port: actualAddr.Port})

	plog.Debug("[SOCKS5] UDP ASSOCIATE on %s", actualAddr)

	// 启动 UDP 转发
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.handleUDPRelay(udpListener)
	}()

	// 等待 TCP 连接关闭（表示 UDP 会话结束）
	buf := make([]byte, 1)
	for {
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}

	// 清理
	udpListener.Close()
	wg.Wait()
}

// handleUDPRelay UDP 数据转发
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

		udpListener.SetReadDeadline(time.Now().Add(UDPSessionIdleTimeout))
		n, clientAddr, err := udpListener.ReadFromUDP(buf)
		if err != nil {
			// 检查是否是超时
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		// 解析 UDP 包
		target, data, err := ParseUDPPacket(buf[:n])
		if err != nil {
			plog.Debug("[SOCKS5] Invalid UDP packet: %v", err)
			continue
		}

		// 获取或创建会话（使用客户端地址作为隔离）
		session, isNew := s.udpSessions.getOrCreate(clientAddr, target, s.streamMgr.NewStreamID, udpListener)

		if isNew {
			plog.Debug("[SOCKS5] New UDP session: %s -> %s (streamID=%d)", clientAddr, target, session.streamID)
			
			// 创建并注册流
			st := stream.NewStream(session.streamID, target, true)
			st.SetState(stream.StateConnecting)
			st.UDPConn = udpListener
			st.UDPClientAddr = clientAddr
			session.stream = st
			s.streamMgr.Register(st)
		}

		// 更新活动时间和客户端地址
		session.touch()
		session.setClientAddr(clientAddr)
		session.setUDPConn(udpListener)

		// 如果会话未打开，发送 Open 命令
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
			
			// 更新流状态
			if session.stream != nil {
				session.stream.SetState(stream.StateConnected)
			}
		}

		// 发送数据
		if s.broadcastFunc != nil {
			if err := s.broadcastFunc(proto.CmdData, session.streamID, data); err != nil {
				plog.Debug("[SOCKS5] Failed to send UDP data: %v", err)
			} else {
				metrics.AddBytesSent(int64(len(data)))
			}
		}
	}
}

// HandleUDPResponse 处理服务端返回的 UDP 响应数据
// 这个方法应该在客户端收到服务端的 UDP 数据时调用
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

	// 解析目标地址用于构建响应包
	host, port, err := proto.ParseHostPort(session.targetAddr)
	if err != nil {
		return err
	}

	// 构建 SOCKS5 UDP 响应包
	responsePacket := BuildUDPPacket(host, port, data)

	// 发送给客户端
	_, err = udpConn.WriteToUDP(responsePacket, clientAddr)
	if err != nil {
		plog.Debug("[SOCKS5] Failed to send UDP response to client: %v", err)
		return err
	}

	session.touch()
	metrics.AddBytesRecv(int64(len(data)))
	
	return nil
}

// HandleUDPClose 处理 UDP 会话关闭
func (s *Server) HandleUDPClose(streamID uint32) {
	session := s.udpSessions.getByStreamID(streamID)
	if session != nil {
		// 注销流
		s.streamMgr.Unregister(streamID)
		// 删除会话
		s.udpSessions.removeByStreamID(streamID)
		plog.Debug("[SOCKS5] UDP session closed: streamID=%d", streamID)
	}
}

// checkIPStrategy 检查 IP 策略
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

// parseIPStrategy 解析 IP 策略字符串
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

// isClosedError 检查是否是关闭错误
func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

// ==================== UDP 包解析 ====================

// ParseUDPPacket 解析 SOCKS5 UDP 包
func ParseUDPPacket(b []byte) (target string, data []byte, err error) {
	if len(b) < 10 {
		return "", nil, errors.New("packet too short")
	}

	// 检查保留字段
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

	// 使用正确的 IPv6 格式化
	target = proto.FormatHostPort(host, port)
	data = b[off:]

	return
}

// BuildUDPPacket 构建 SOCKS5 UDP 包
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


