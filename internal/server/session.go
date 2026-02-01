
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
	DefaultMaxRetries          = 3
	DefaultRetryDelay          = 100 * time.Millisecond
	GracefulShutdownTimeout    = 30 * time.Second
)

// ==================== 错误定义 ====================

var (
	ErrSessionClosed   = errors.New("session closed")
	ErrStreamLimitHit  = errors.New("stream limit exceeded")
	ErrWriteQueueFull  = errors.New("write queue full")
	ErrSendTimeout     = errors.New("send timeout")
	ErrInvalidPayload  = errors.New("invalid payload")
	ErrDialFailed      = errors.New("dial failed")
	ErrInvalidHost     = errors.New("invalid host")
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
	MaxRetries        int
	RetryDelay        time.Duration
}

// DefaultSessionConfig 返回默认配置
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
		MaxRetries:        DefaultMaxRetries,
		RetryDelay:        DefaultRetryDelay,
	}
}

// ==================== 会话定义 ====================

// Session 处理单个客户端连接
type Session struct {
	id        string
	conn      *transport.WSConn
	streamMgr *stream.Manager
	cfg       *config.ServerConfig
	sessCfg   *SessionConfig
	writeCh   chan transport.WriteJob

	// 生命周期控制
	ctx        context.Context
	cancel     context.CancelFunc
	stopOnce   sync.Once
	stopped    int32
	wg         sync.WaitGroup
	startTime  time.Time
	lastActive int64 // Unix timestamp，原子操作

	// 统计信息
	streamCount    int32
	streamsCreated int64
	streamsClosed  int64
	bytesSent      int64
	bytesRecv      int64
	packetsSent    int64
	packetsRecv    int64
	errorCount     int64
}

// NewSession 创建新会话
func NewSession(id string, conn *websocket.Conn, mgr *stream.Manager, cfg *config.ServerConfig) *Session {
	ctx, cancel := context.WithCancel(context.Background())

	sessCfg := DefaultSessionConfig()

	// 从服务端配置覆盖
	if cfg.MaxStreamsPerConn > 0 {
		sessCfg.MaxStreamsPerConn = cfg.MaxStreamsPerConn
	}
	if cfg.WriteTimeout > 0 {
		sessCfg.WriteTimeout = cfg.WriteTimeout
		// 发送超时使用写超时的一半
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

// ID 返回会话 ID
func (s *Session) ID() string {
	return s.id
}

// IsStopped 检查会话是否已停止
func (s *Session) IsStopped() bool {
	return atomic.LoadInt32(&s.stopped) == 1
}

// Stop 停止会话
func (s *Session) Stop() {
	s.stopOnce.Do(func() {
		atomic.StoreInt32(&s.stopped, 1)
		s.cancel()
	})
}

// updateLastActive 更新最后活动时间
func (s *Session) updateLastActive() {
	atomic.StoreInt64(&s.lastActive, time.Now().Unix())
}

// GetStats 获取会话统计信息
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

// Serve 主服务循环
func (s *Session) Serve() {
	defer s.cleanup()

	// 启动写循环
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.writeLoop()
	}()

	// 读循环（阻塞）
	s.readLoop()
}

// cleanup 清理资源
func (s *Session) cleanup() {
	s.Stop()

	// 等待所有 goroutine 完成（带超时）
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

	// 关闭所有流
	s.streamMgr.CloseAll()

	// 关闭连接
	s.conn.Close()

	// 排空写队列
	s.drainWriteChannel()

	plog.Info("[Session] %s closed, stats: created=%d, closed=%d, current=%d",
		s.id,
		atomic.LoadInt64(&s.streamsCreated),
		atomic.LoadInt64(&s.streamsClosed),
		atomic.LoadInt32(&s.streamCount))
}

// drainWriteChannel 排空写队列
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

// writeLoop 写循环
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

// handleWriteError 处理写错误
func (s *Session) handleWriteError(job transport.WriteJob, err error) {
	atomic.AddInt64(&s.errorCount, 1)
	if job.Done != nil {
		select {
		case job.Done <- err:
		default:
		}
	}
}

// readLoop 读循环
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

// handleFrame 处理帧
func (s *Session) handleFrame(data []byte) {
	cmd, streamID, flags, payload, err := proto.UnpackFrameWithPadding(data)
	if err != nil {
		plog.Debug("[Session] %s unpack error: %v", s.id, err)
		atomic.AddInt64(&s.errorCount, 1)
		return
	}

	// 处理聚合包
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

// handleTCPOpen 处理 TCP 打开请求
func (s *Session) handleTCPOpen(streamID uint32, payload []byte) {
	// 先增加计数，如果超限则回滚
	newCount := atomic.AddInt32(&s.streamCount, 1)
	maxStreams := int32(s.sessCfg.MaxStreamsPerConn)

	if newCount > maxStreams {
		atomic.AddInt32(&s.streamCount, -1)
		plog.Warn("[Session] %s stream limit exceeded (current: %d, max: %d)",
			s.id, newCount-1, maxStreams)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	// 解析 payload
	ipStrategy, host, port, initData, err := proto.ParseOpenPayload(payload)
	if err != nil {
		atomic.AddInt32(&s.streamCount, -1)
		plog.Debug("[Session] %s parse open payload error: %v", s.id, err)
		atomic.AddInt64(&s.errorCount, 1)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	// 验证并清理 host
	host, err = proto.SanitizeHost(host)
	if err != nil {
		atomic.AddInt32(&s.streamCount, -1)
		plog.Warn("[Session] %s invalid host: %v", s.id, err)
		atomic.AddInt64(&s.errorCount, 1)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	// 使用正确的 IPv6 格式化
	target := proto.FormatHostPort(host, port)
	dialTarget := s.resolveWithStrategy(host, port, ipStrategy)

	// 建立连接
	conn, err := net.DialTimeout("tcp", dialTarget, 10*time.Second)
	if err != nil {
		atomic.AddInt32(&s.streamCount, -1)
		plog.Debug("[Session] %s TCP dial failed: %s: %v", s.id, target, err)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	// 创建流
	st := stream.NewStream(streamID, target, false)
	st.TCPConn = conn
	st.SetState(stream.StateConnected)
	st.OnClose = func(id uint32) {
		atomic.AddInt32(&s.streamCount, -1)
		atomic.AddInt64(&s.streamsClosed, 1)
		// 只有在会话未停止时才发送关闭帧
		if !s.IsStopped() {
			s.send(proto.CmdClose, id, nil)
		}
	}
	s.streamMgr.Register(st)
	atomic.AddInt64(&s.streamsCreated, 1)

	// 0-RTT: 发送 InitData
	if len(initData) > 0 {
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(initData); err != nil {
			plog.Debug("[Session] %s InitData write failed: %v", s.id, err)
			s.streamMgr.Unregister(st.ID)
			return
		}
		conn.SetWriteDeadline(time.Time{})
	}

	// 发送成功响应
	s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusOK})

	// 日志脱敏：非 debug 级别下隐藏敏感信息
	logTarget := sanitizeTarget(target, isDebugLevel())
	plog.Info("[Session] %s TCP stream %d -> %s (init: %d bytes)", s.id, streamID, logTarget, len(initData))

	// 启动读循环
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.tcpReadLoop(st)
	}()
}

// handleUDPOpen 处理 UDP 打开请求
func (s *Session) handleUDPOpen(streamID uint32, payload []byte) {
	// 先增加计数，如果超限则回滚
	newCount := atomic.AddInt32(&s.streamCount, 1)
	maxStreams := int32(s.sessCfg.MaxStreamsPerConn)

	if newCount > maxStreams {
		atomic.AddInt32(&s.streamCount, -1)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	// 解析 payload
	ipStrategy, host, port, _, err := proto.ParseOpenPayload(payload)
	if err != nil {
		atomic.AddInt32(&s.streamCount, -1)
		atomic.AddInt64(&s.errorCount, 1)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	// 验证并清理 host
	host, err = proto.SanitizeHost(host)
	if err != nil {
		atomic.AddInt32(&s.streamCount, -1)
		atomic.AddInt64(&s.errorCount, 1)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	// 使用正确的 IPv6 格式化
	target := proto.FormatHostPort(host, port)

	// 创建 UDP 连接
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		atomic.AddInt32(&s.streamCount, -1)
		s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
		return
	}

	// 解析目标地址
	targetIP := net.ParseIP(host)
	if targetIP == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			udpConn.Close()
			atomic.AddInt32(&s.streamCount, -1)
			s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusFail})
			return
		}
		targetIP = selectIPByStrategy(ips, ipStrategy)
	}

	udpAddr := &net.UDPAddr{IP: targetIP, Port: int(port)}

	// 创建流
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

	// 发送成功响应
	s.send(proto.CmdConnStatus, streamID, []byte{proto.StatusOK})

	// 日志脱敏
	logTarget := sanitizeTarget(target, isDebugLevel())
	plog.Info("[Session] %s UDP stream %d -> %s", s.id, streamID, logTarget)

	// 启动读循环
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.udpReadLoop(st)
	}()
}

// handleData 处理数据帧
func (s *Session) handleData(streamID uint32, payload []byte) {
	st := s.streamMgr.Get(streamID)
	if st == nil {
		return
	}

	if _, err := st.Write(payload); err != nil {
		s.handleClose(streamID)
	}
}

// handleClose 处理关闭请求
func (s *Session) handleClose(streamID uint32) {
	s.streamMgr.Unregister(streamID)
}

// tcpReadLoop TCP 读循环
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

		st.TCPConn.SetReadDeadline(time.Now().Add(s.sessCfg.TCPReadTimeout))
		n, err := st.TCPConn.Read(buf)
		if err != nil {
			if !st.IsClosed() && !s.IsStopped() {
				// 检查是否是超时错误
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// 超时不是错误，继续
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

// udpReadLoop UDP 读循环
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

		st.UDPConn.SetReadDeadline(time.Now().Add(s.sessCfg.UDPReadTimeout))
		n, addr, err := st.UDPConn.ReadFromUDP(buf)
		if err != nil {
			// 检查是否是超时错误
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// UDP 超时不关闭连接，继续等待
				continue
			}
			if !st.IsClosed() && !s.IsStopped() {
				s.send(proto.CmdClose, st.ID, nil)
			}
			return
		}

		if n > 0 {
			// 使用正确的 IPv6 格式化
			host := addr.IP.String()
			port := uint16(addr.Port)
			payload := proto.BuildOpenPayload(0, host, port, buf[:n])
			s.send(proto.CmdData, st.ID, payload)
		}
	}
}

// send 发送帧（异步）
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

// sendSync 同步发送帧
func (s *Session) sendSync(cmd byte, streamID uint32, payload []byte, timeout time.Duration) error {
	if s.IsStopped() {
		return ErrSessionClosed
	}

	frame := proto.PackFrameAlloc(cmd, streamID, payload)
	done := make(chan error, 1)

	select {
	case s.writeCh <- transport.WriteJob{Data: frame, Done: done}:
	case <-time.After(timeout):
		return ErrWriteQueueFull
	case <-s.ctx.Done():
		return ErrSessionClosed
	}

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return ErrSendTimeout
	case <-s.ctx.Done():
		return ErrSessionClosed
	}
}

// sendWithRetry 带重试的发送
func (s *Session) sendWithRetry(cmd byte, streamID uint32, payload []byte) error {
	var lastErr error
	for i := 0; i < s.sessCfg.MaxRetries; i++ {
		if s.IsStopped() {
			return ErrSessionClosed
		}

		lastErr = s.sendSync(cmd, streamID, payload, s.sessCfg.SendTimeout)
		if lastErr == nil {
			return nil
		}

		// 指数退避
		delay := s.sessCfg.RetryDelay * time.Duration(1<<uint(i))
		select {
		case <-time.After(delay):
		case <-s.ctx.Done():
			return ErrSessionClosed
		}
	}
	return lastErr
}

// ==================== 辅助函数 ====================

// resolveWithStrategy 根据 IP 策略解析地址
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

// selectIPByStrategy 根据策略选择 IP
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

// sanitizeTarget 对目标地址进行脱敏处理
// 在 info 级别下只显示域名/部分IP，debug 级别下显示完整地址
func sanitizeTarget(target string, fullLog bool) string {
	if fullLog {
		return target
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "***"
	}

	// 检查是否是 IP 地址
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			// IPv4: 192.168.1.100 -> 192.168.*.*
			parts := strings.Split(host, ".")
			if len(parts) == 4 {
				return fmt.Sprintf("%s.%s.*.*:%s", parts[0], parts[1], port)
			}
		} else {
			// IPv6: 简化显示
			parts := strings.Split(host, ":")
			if len(parts) >= 2 {
				return fmt.Sprintf("[%s::*]:%s", parts[0], port)
			}
		}
		return fmt.Sprintf("*.*.*.*:%s", port)
	}

	// 域名：显示主域名
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		// api.secret.example.com -> *.example.com
		return fmt.Sprintf("*.%s.%s:%s", parts[len(parts)-2], parts[len(parts)-1], port)
	}

	return target
}

// isDebugLevel 检查是否为 debug 日志级别
func isDebugLevel() bool {
	return plog.GetLevel() <= plog.DEBUG
}




