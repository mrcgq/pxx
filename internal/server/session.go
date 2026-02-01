


//internal/server/session.go

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"phantom-x/internal/proto"
	"phantom-x/internal/stream"
	"phantom-x/internal/transport"
	"phantom-x/pkg/config"
	plog "phantom-x/pkg/log"
	"phantom-x/pkg/metrics"
)

// ==================== 常量定义 ====================

const (
	DefaultMaxStreamsPerClient = 1000
	DefaultWriteChannelSize    = 4096
	DefaultSendTimeout         = 5 * time.Second
	DefaultTCPReadTimeout      = 120 * time.Second
	DefaultUDPReadTimeout      = 120 * time.Second
	DefaultWriteTimeout        = 10 * time.Second
	DefaultReadTimeout         = 60 * time.Second
	DefaultPingInterval        = 30 * time.Second
	GracefulShutdownTimeout    = 30 * time.Second
)

// ==================== 错误定义 ====================

var (
	ErrSessionClosed  = errors.New("session closed")
	ErrStreamLimitHit = errors.New("stream limit exceeded")
	ErrWriteQueueFull = errors.New("write queue full")
	ErrSendTimeout    = errors.New("send timeout")
	ErrInvalidPayload = errors.New("invalid payload")
	ErrDialFailed     = errors.New("dial failed")
	ErrInvalidHost    = errors.New("invalid host")
)

// ==================== 会话统计 ====================

type SessionStats struct {
	StreamsCreated   int64
	StreamsClosed    int64
	BytesSent        int64
	BytesRecv        int64
	PacketsSent      int64
	PacketsRecv      int64
	ErrorCount       int64
	CurrentStreams   int32
	WriteQueueLen    int
	Uptime           time.Duration
	LastActivityTime time.Time
}

// ==================== 会话配置 ====================

type SessionConfig struct {
	MaxStreamsPerConn int
	WriteChannelSize  int
	SendTimeout       time.Duration
	WriteTimeout      time.Duration
	ReadTimeout       time.Duration
	TCPReadTimeout    time.Duration
	UDPReadTimeout    time.Duration
	PingInterval      time.Duration
}

func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		MaxStreamsPerConn: DefaultMaxStreamsPerClient,
		WriteChannelSize:  DefaultWriteChannelSize,
		SendTimeout:       DefaultSendTimeout,
		WriteTimeout:      DefaultWriteTimeout,
		ReadTimeout:       DefaultReadTimeout,
		TCPReadTimeout:    DefaultTCPReadTimeout,
		UDPReadTimeout:    DefaultUDPReadTimeout,
		PingInterval:      DefaultPingInterval,
	}
}

// ==================== 会话定义 ====================

type Session struct {
	id        string
	conn      *transport.WSConn
	streamMgr *stream.Manager
	cfg       *config.ServerConfig
	sessCfg   *SessionConfig
	writeCh   chan transport.WriteJob

	ctx        context.Context
	cancel     context.CancelFunc
	stopOnce   sync.Once
	stopped    int32
	wg         sync.WaitGroup
	startTime  time.Time
	lastActive int64

	streamCount    int32
	streamsCreated int64
	streamsClosed  int64
	bytesSent      int64
	bytesRecv      int64
	packetsSent    int64
	packetsRecv    int64
	errorCount     int64
}

func NewSession(id string, conn *websocket.Conn, mgr *stream.Manager, cfg *config.ServerConfig) *Session {
	ctx, cancel := context.WithCancel(context.Background())

	sessCfg := DefaultSessionConfig()

	if cfg.MaxStreamsPerConn > 0 {
		sessCfg.MaxStreamsPerConn = cfg.MaxStreamsPerConn
	}
	if cfg.WriteTimeout > 0 {
		sessCfg.WriteTimeout = cfg.WriteTimeout
		sessCfg.SendTimeout = cfg.WriteTimeout / 2
		if sessCfg.SendTimeout < 100*time.Millisecond {
			sessCfg.SendTimeout = 100 * time.Millisecond
		}
	}
	if cfg.ReadTimeout > 0 {
		sessCfg.ReadTimeout = cfg.ReadTimeout
	}

	wsConn := transport.NewWSConn(0, conn, sessCfg.WriteChannelSize)

	return &Session{
		id:         id,
		conn:       wsConn,
		streamMgr:  mgr,
		cfg:        cfg,
		sessCfg:    sessCfg,
		writeCh:    make(chan transport.WriteJob, sessCfg.WriteChannelSize),
		ctx:        ctx,
		cancel:     cancel,
		startTime:  time.Now(),
		lastActive: time.Now().Unix(),
	}
}

func (s *Session) ID() string {
	return s.id
}

func (s *Session) IsStopped() bool {
	return atomic.LoadInt32(&s.stopped) == 1
}

func (s *Session) Stop() {
	s.stopOnce.Do(func() {
		atomic.StoreInt32(&s.stopped, 1)
		s.cancel()
	})
}

func (s *Session) updateLastActive() {
	atomic.StoreInt64(&s.lastActive, time.Now().Unix())
}

func (s *Session) GetStats() SessionStats {
	return SessionStats{
		StreamsCreated:   atomic.LoadInt64(&s.streamsCreated),
		StreamsClosed:    atomic.LoadInt64(&s.streamsClosed),
		BytesSent:        atomic.LoadInt64(&s.bytesSent),
		BytesRecv:        atomic.LoadInt64(&s.bytesRecv),
		PacketsSent:      atomic.LoadInt64(&s.packetsSent),
		PacketsRecv:      atomic.LoadInt64(&s.packetsRecv),
		ErrorCount:       atomic.LoadInt64(&s.errorCount),
		CurrentStreams:   atomic.LoadInt32(&s.streamCount),
		WriteQueueLen:    len(s.writeCh),
		Uptime:           time.Since(s.startTime),
		LastActivityTime: time.Unix(atomic.LoadInt64(&s.lastActive), 0),
	}
}

func (s *Session) Serve() {
	defer s.cleanup()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.writeLoop()
	}()

	s.readLoop()
}

func (s *Session) cleanup() {
	s.Stop()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		plog.Debug("[Session] %s all goroutines stopped", s.id)
	case <-time.After(GracefulShutdownTimeout):
		plog.Warn("[Session] %s graceful shutdown timeout", s.id)
	}

	s.streamMgr.CloseAll()
	s.conn.Close()
	s.drainWriteChannel()

	plog.Info("[Session] %s closed, stats: created=%d, closed=%d, current=%d",
		s.id,
		atomic.LoadInt64(&s.streamsCreated),
		atomic.LoadInt64(&s.streamsClosed),
		atomic.LoadInt32(&s.streamCount))
}

func (s *Session) drainWriteChannel() {
	for {
		select {
		case job, ok := <-s.writeCh:
			if !ok {
				return
			}
			if job.Done != nil {
				select {
				case job.Done <- ErrSessionClosed:
				default:
				}
			}
		default:
			return
		}
	}
}

func (s *Session) writeLoop() {
	ticker := time.NewTicker(s.sessCfg.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return

		case job, ok := <-s.writeCh:
			if !ok {
				return
			}

			if err := s.conn.SetWriteDeadline(time.Now().Add(s.sessCfg.WriteTimeout)); err != nil {
				s.handleWriteError(job, err)
				return
			}

			if err := s.conn.WriteMessage(websocket.BinaryMessage, job.Data); err != nil {
				s.handleWriteError(job, err)
				plog.Debug("[Session] %s write error: %v", s.id, err)
				return
			}

			atomic.AddInt64(&s.packetsSent, 1)
			atomic.AddInt64(&s.bytesSent, int64(len(job.Data)))
			metrics.IncrPacketsSent(1)
			metrics.AddBytesSent(int64(len(job.Data)))

			if job.Done != nil {
				select {
				case job.Done <- nil:
				default:
				}
			}

		case <-ticker.C:
			if err := s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return
			}
			if err := s.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (s *Session) handleWriteError(job transport.WriteJob, err error) {
	atomic.AddInt64(&s.errorCount, 1)
	if job.Done != nil {
		select {
		case job.Done <- err:
		default:
		}
	}
}

func (s *Session) readLoop() {
	s.conn.SetPongHandler(func(string) error {
		s.updateLastActive()
		return s.conn.SetReadDeadline(time.Now().Add(s.sessCfg.ReadTimeout))
	})

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		if err := s.conn.SetReadDeadline(time.Now().Add(s.sessCfg.ReadTimeout)); err != nil {
			return
		}

		mt, data, err := s.conn.ReadMessage()
		if err != nil {
			if !transport.IsNormalClose(err) {
				plog.Debug("[Session] %s read error: %v", s.id, err)
			}
			return
		}

		if mt != websocket.BinaryMessage || len(data) < proto.HeaderLen {
			continue
		}

		s.updateLastActive()
		atomic.AddInt64(&s.packetsRecv, 1)
		atomic.AddInt64(&s.bytesRecv, int64(len(data)))
		metrics.IncrPacketsRecv(1)
		metrics.AddBytesRecv(int64(len(data)))

		s.handleFrame(data)
	}
}

func (s *Session) handleFrame(data []byte) {
	cmd, streamID, flags, payload, err := proto.UnpackFrameWithPadding(data)
	if err != nil {
		plog.Debug("[Session] %s unpack error: %v", s.id, err)
		atomic.AddInt64(&s.errorCount, 1)
		return
	}

	if cmd == proto.CmdData && flags&proto.FlagAggregate != 0 {
		agg, err := proto.DecodeAggregatedData(payload)
		if err != nil {
			plog.Debug("[Session] %s decode aggregate error: %v", s.id, err)
			atomic.AddInt64(&s.errorCount, 1)
			return
		}
		for _, item := range agg.Items {
			s.handleData(item.StreamID, item.Data)
		}
		return
	}

	switch cmd {
	case proto.CmdOpenTCP:
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleTCPOpen(streamID, payload)
		}()
	case proto.CmdOpenUDP:
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleUDPOpen(streamID, payload)
		}()
	case proto.CmdData:
		s.handleData(streamID, payload)
	case proto.CmdClose:
		s.handleClose(streamID)
	case proto.CmdPing:
		s.send(proto.CmdPong, streamID, nil)
	}
}

func (s *Session) handleTCPOpen(streamID uint32, payload []byte) {
	newCount := atomic.AddInt32(&s.streamCount, 1)
	maxStreams := int32(s.sessCfg.MaxStreamsPerConn)

	if newCount > maxStreams {
		atomic.AddInt32(&s.streamCount, -1)
		plog.Warn("[Session] %s stream limit exceeded (current: %d, max: %d)",
			s.id, newCount-1, maxStreams)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	ipStrategy, host, port, initData, err := proto.ParseOpenPayload(payload)
	if err != nil {
		atomic.AddInt32(&s.streamCount, -1)
		plog.Debug("[Session] %s parse open payload error: %v", s.id, err)
		atomic.AddInt64(&s.errorCount, 1)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	host, err = proto.SanitizeHost(host)
	if err != nil {
		atomic.AddInt32(&s.streamCount, -1)
		plog.Warn("[Session] %s invalid host: %v", s.id, err)
		atomic.AddInt64(&s.errorCount, 1)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	target := proto.FormatHostPort(host, port)
	dialTarget := s.resolveWithStrategy(host, port, ipStrategy)

	conn, err := net.DialTimeout("tcp", dialTarget, 10*time.Second)
	if err != nil {
		atomic.AddInt32(&s.streamCount, -1)
		plog.Debug("[Session] %s TCP dial failed: %s: %v", s.id, target, err)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	st := stream.NewStream(streamID, target, false)
	st.TCPConn = conn
	st.SetState(stream.StateConnected)
	st.OnClose = func(id uint32) {
		atomic.AddInt32(&s.streamCount, -1)
		atomic.AddInt64(&s.streamsClosed, 1)
		if !s.IsStopped() {
			s.send(proto.CmdClose, id, nil)
		}
	}
	s.streamMgr.Register(st)
	atomic.AddInt64(&s.streamsCreated, 1)

	if len(initData) > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			plog.Debug("[Session] %s SetWriteDeadline failed: %v", s.id, err)
			s.streamMgr.Unregister(st.ID)
			return
		}
		if _, err := conn.Write(initData); err != nil {
			plog.Debug("[Session] %s InitData write failed: %v", s.id, err)
			s.streamMgr.Unregister(st.ID)
			return
		}
		_ = conn.SetWriteDeadline(time.Time{})
	}

	s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusOK})

	logTarget := sanitizeTarget(target, isDebugLevel())
	plog.Info("[Session] %s TCP stream %d -> %s (init: %d bytes)", s.id, streamID, logTarget, len(initData))

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.tcpReadLoop(st)
	}()
}

func (s *Session) handleUDPOpen(streamID uint32, payload []byte) {
	newCount := atomic.AddInt32(&s.streamCount, 1)
	maxStreams := int32(s.sessCfg.MaxStreamsPerConn)

	if newCount > maxStreams {
		atomic.AddInt32(&s.streamCount, -1)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	ipStrategy, host, port, _, err := proto.ParseOpenPayload(payload)
	if err != nil {
		atomic.AddInt32(&s.streamCount, -1)
		atomic.AddInt64(&s.errorCount, 1)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	host, err = proto.SanitizeHost(host)
	if err != nil {
		atomic.AddInt32(&s.streamCount, -1)
		atomic.AddInt64(&s.errorCount, 1)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	target := proto.FormatHostPort(host, port)

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		atomic.AddInt32(&s.streamCount, -1)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	targetIP := net.ParseIP(host)
	if targetIP == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			_ = udpConn.Close()
			atomic.AddInt32(&s.streamCount, -1)
			s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
			return
		}
		targetIP = selectIPByStrategy(ips, ipStrategy)
	}

	udpAddr := &net.UDPAddr{IP: targetIP, Port: int(port)}

	st := stream.NewStream(streamID, target, true)
	st.UDPConn = udpConn
	st.UDPAddr = udpAddr
	st.SetState(stream.StateConnected)
	st.OnClose = func(id uint32) {
		atomic.AddInt32(&s.streamCount, -1)
		atomic.AddInt64(&s.streamsClosed, 1)
		if !s.IsStopped() {
			s.send(proto.CmdClose, id, nil)
		}
	}
	s.streamMgr.Register(st)
	atomic.AddInt64(&s.streamsCreated, 1)

	s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusOK})

	logTarget := sanitizeTarget(target, isDebugLevel())
	plog.Info("[Session] %s UDP stream %d -> %s", s.id, streamID, logTarget)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.udpReadLoop(st)
	}()
}

func (s *Session) handleData(streamID uint32, payload []byte) {
	st := s.streamMgr.Get(streamID)
	if st == nil {
		return
	}

	if _, err := st.Write(payload); err != nil {
		s.handleClose(streamID)
	}
}

func (s *Session) handleClose(streamID uint32) {
	s.streamMgr.Unregister(streamID)
}

func (s *Session) tcpReadLoop(st *stream.Stream) {
	bufPtr := transport.GetBuffer(32 * 1024)
	buf := *bufPtr
	defer func() {
		transport.PutBuffer(bufPtr)
		s.streamMgr.Unregister(st.ID)
	}()

	for {
		if st.IsClosed() || s.IsStopped() {
			return
		}

		if err := st.TCPConn.SetReadDeadline(time.Now().Add(s.sessCfg.TCPReadTimeout)); err != nil {
			return
		}
		n, err := st.TCPConn.Read(buf)
		if err != nil {
			if !st.IsClosed() && !s.IsStopped() {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				s.send(proto.CmdClose, st.ID, nil)
			}
			return
		}

		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			s.send(proto.CmdData, st.ID, data)
		}
	}
}

func (s *Session) udpReadLoop(st *stream.Stream) {
	bufPtr := transport.GetBuffer(64 * 1024)
	buf := *bufPtr
	defer func() {
		transport.PutBuffer(bufPtr)
		s.streamMgr.Unregister(st.ID)
	}()

	for {
		if st.IsClosed() || s.IsStopped() {
			return
		}

		if err := st.UDPConn.SetReadDeadline(time.Now().Add(s.sessCfg.UDPReadTimeout)); err != nil {
			return
		}
		n, addr, err := st.UDPConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if !st.IsClosed() && !s.IsStopped() {
				s.send(proto.CmdClose, st.ID, nil)
			}
			return
		}

		if n > 0 {
			host := addr.IP.String()
			port := uint16(addr.Port)
			payload := proto.BuildOpenPayload(0, host, port, buf[:n])
			s.send(proto.CmdData, st.ID, payload)
		}
	}
}

func (s *Session) send(cmd byte, streamID uint32, payload []byte) {
	if s.IsStopped() {
		return
	}

	frame := proto.PackFrameAlloc(cmd, streamID, payload)
	select {
	case s.writeCh <- transport.WriteJob{Data: frame}:
	case <-time.After(s.sessCfg.SendTimeout):
		plog.Warn("[Session] %s write queue full, dropping frame for stream %d (cmd=%d)",
			s.id, streamID, cmd)
		atomic.AddInt64(&s.errorCount, 1)
		metrics.IncrWriteTimeout()
	case <-s.ctx.Done():
	}
}

// ==================== 辅助函数 ====================

func (s *Session) resolveWithStrategy(host string, port uint16, strategy byte) string {
	if strategy == proto.IPDefault {
		return proto.FormatHostPort(host, port)
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return proto.FormatHostPort(host, port)
	}

	ip := selectIPByStrategy(ips, strategy)
	return proto.FormatHostPort(ip.String(), port)
}

func selectIPByStrategy(ips []net.IP, strategy byte) net.IP {
	var ipv4s, ipv6s []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip)
		} else {
			ipv6s = append(ipv6s, ip)
		}
	}

	switch strategy {
	case proto.IPv4Only:
		if len(ipv4s) > 0 {
			return ipv4s[0]
		}
	case proto.IPv6Only:
		if len(ipv6s) > 0 {
			return ipv6s[0]
		}
	case proto.IPv4First:
		if len(ipv4s) > 0 {
			return ipv4s[0]
		}
		if len(ipv6s) > 0 {
			return ipv6s[0]
		}
	case proto.IPv6First:
		if len(ipv6s) > 0 {
			return ipv6s[0]
		}
		if len(ipv4s) > 0 {
			return ipv4s[0]
		}
	}

	return ips[0]
}

func sanitizeTarget(target string, fullLog bool) string {
	if fullLog {
		return target
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "***"
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			parts := strings.Split(host, ".")
			if len(parts) == 4 {
				return fmt.Sprintf("%s.%s.*.*:%s", parts[0], parts[1], port)
			}
		} else {
			parts := strings.Split(host, ":")
			if len(parts) >= 2 {
				return fmt.Sprintf("[%s::*]:%s", parts[0], port)
			}
		}
		return fmt.Sprintf("*.*.*.*:%s", port)
	}

	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		return fmt.Sprintf("*.%s.%s:%s", parts[len(parts)-2], parts[len(parts)-1], port)
	}

	return target
}

func isDebugLevel() bool {
	return plog.GetLevel() <= plog.DEBUG
}


