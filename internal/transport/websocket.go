

//internal/transport/websocket.go

package transport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"phantom-x/internal/ech"
	"phantom-x/pkg/config"
	"phantom-x/pkg/metrics"
)

// ==================== 常量定义 ====================

const (
	TokenValiditySeconds = 300
	DefaultWriteTimeout  = 10 * time.Second
	DefaultReadTimeout   = 60 * time.Second
	DefaultPingInterval  = 30 * time.Second
	DefaultWriteQueueSize = 4096
	CloseGracePeriod     = 5 * time.Second
)

// ==================== 错误定义 ====================

var (
	ErrConnectionClosed   = errors.New("connection closed")
	ErrWriteTimeout       = errors.New("write timeout")
	ErrWriteQueueFull     = errors.New("write queue full")
	ErrConnectionClosing  = errors.New("connection closing")
	ErrAuthFailed         = errors.New("authentication failed")
)

// ==================== 写任务 ====================

type WriteJob struct {
	Data     []byte
	Priority bool
	Done     chan error
}

// ==================== WebSocket 连接包装器 ====================

type WSConn struct {
	ID         int
	conn       *websocket.Conn
	writeCh    chan WriteJob
	closed     int32
	ctx        context.Context
	cancel     context.CancelFunc
	closeOnce  sync.Once
	closeMu    sync.Mutex
	
	// 活跃时间
	lastActive int64 // Unix nano
	
	// 统计
	bytesSent   int64
	bytesRecv   int64
	packetsSent int64
	packetsRecv int64
	
	// 配置
	writeTimeout time.Duration
	readTimeout  time.Duration
}

func NewWSConn(id int, conn *websocket.Conn, queueSize int) *WSConn {
	if queueSize <= 0 {
		queueSize = DefaultWriteQueueSize
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	return &WSConn{
		ID:           id,
		conn:         conn,
		writeCh:      make(chan WriteJob, queueSize),
		ctx:          ctx,
		cancel:       cancel,
		lastActive:   time.Now().UnixNano(),
		writeTimeout: DefaultWriteTimeout,
		readTimeout:  DefaultReadTimeout,
	}
}

// SetWriteTimeout 设置写超时
func (w *WSConn) SetWriteTimeout(d time.Duration) {
	w.writeTimeout = d
}

// SetReadTimeout 设置读超时
func (w *WSConn) SetReadTimeout(d time.Duration) {
	w.readTimeout = d
}

// Send 异步发送数据
func (w *WSConn) Send(data []byte, priority bool) error {
	if w.IsClosed() {
		return ErrConnectionClosed
	}

	job := WriteJob{
		Data:     data,
		Priority: priority,
	}

	// 优先消息直接尝试发送
	if priority {
		select {
		case w.writeCh <- job:
			return nil
		default:
			// 队列满，尝试等待
		}
	}

	select {
	case w.writeCh <- job:
		return nil
	case <-time.After(w.writeTimeout):
		metrics.IncrWriteTimeout()
		return ErrWriteTimeout
	case <-w.ctx.Done():
		return ErrConnectionClosing
	}
}

// SendSync 同步发送数据，等待写入完成
func (w *WSConn) SendSync(data []byte, timeout time.Duration) error {
	if w.IsClosed() {
		return ErrConnectionClosed
	}

	if timeout <= 0 {
		timeout = w.writeTimeout
	}

	job := WriteJob{
		Data:     data,
		Priority: true,
		Done:     make(chan error, 1),
	}

	// 发送到队列
	select {
	case w.writeCh <- job:
	case <-time.After(timeout):
		return ErrWriteQueueFull
	case <-w.ctx.Done():
		return ErrConnectionClosing
	}

	// 等待写入完成
	select {
	case err := <-job.Done:
		return err
	case <-time.After(timeout):
		return ErrWriteTimeout
	case <-w.ctx.Done():
		return ErrConnectionClosing
	}
}

// Close 关闭连接
func (w *WSConn) Close() {
	w.closeOnce.Do(func() {
		atomic.StoreInt32(&w.closed, 1)
		
		// 取消 context
		w.cancel()

		// 尝试发送关闭帧
		if w.conn != nil {
			w.conn.SetWriteDeadline(time.Now().Add(CloseGracePeriod))
			w.conn.WriteMessage(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			)
			w.conn.Close()
		}

		// 排空写队列并通知等待者
		w.drainWriteChannel()
	})
}

// drainWriteChannel 安全地排空写通道
func (w *WSConn) drainWriteChannel() {
	for {
		select {
		case job, ok := <-w.writeCh:
			if !ok {
				return
			}
			if job.Done != nil {
				select {
				case job.Done <- ErrConnectionClosed:
				default:
				}
			}
		default:
			return
		}
	}
}

// IsClosed 检查连接是否已关闭
func (w *WSConn) IsClosed() bool {
	return atomic.LoadInt32(&w.closed) == 1
}

// UpdateActive 更新活跃时间
func (w *WSConn) UpdateActive() {
	atomic.StoreInt64(&w.lastActive, time.Now().UnixNano())
}

// GetLastActive 获取最后活跃时间
func (w *WSConn) GetLastActive() time.Time {
	return time.Unix(0, atomic.LoadInt64(&w.lastActive))
}

// IdleDuration 获取空闲时长
func (w *WSConn) IdleDuration() time.Duration {
	return time.Since(w.GetLastActive())
}

// WriteMessage 直接写入消息（用于控制帧）
func (w *WSConn) WriteMessage(msgType int, data []byte) error {
	if w.IsClosed() {
		return ErrConnectionClosed
	}
	
	w.closeMu.Lock()
	defer w.closeMu.Unlock()
	
	if w.conn == nil {
		return ErrConnectionClosed
	}
	
	w.conn.SetWriteDeadline(time.Now().Add(w.writeTimeout))
	err := w.conn.WriteMessage(msgType, data)
	if err == nil {
		atomic.AddInt64(&w.bytesSent, int64(len(data)))
		atomic.AddInt64(&w.packetsSent, 1)
		w.UpdateActive()
	}
	return err
}

// ReadMessage 读取消息
func (w *WSConn) ReadMessage() (int, []byte, error) {
	if w.IsClosed() {
		return 0, nil, ErrConnectionClosed
	}
	
	msgType, data, err := w.conn.ReadMessage()
	if err == nil {
		atomic.AddInt64(&w.bytesRecv, int64(len(data)))
		atomic.AddInt64(&w.packetsRecv, 1)
		w.UpdateActive()
	}
	return msgType, data, err
}

// SetReadDeadline 设置读取超时
func (w *WSConn) SetReadDeadline(t time.Time) error {
	if w.conn == nil {
		return ErrConnectionClosed
	}
	return w.conn.SetReadDeadline(t)
}

// SetWriteDeadline 设置写入超时
func (w *WSConn) SetWriteDeadline(t time.Time) error {
	if w.conn == nil {
		return ErrConnectionClosed
	}
	return w.conn.SetWriteDeadline(t)
}

// SetPongHandler 设置 Pong 处理器
func (w *WSConn) SetPongHandler(h func(string) error) {
	if w.conn != nil {
		w.conn.SetPongHandler(h)
	}
}

// SetPingHandler 设置 Ping 处理器
func (w *WSConn) SetPingHandler(h func(string) error) {
	if w.conn != nil {
		w.conn.SetPingHandler(h)
	}
}

// Ping 发送 Ping 帧
func (w *WSConn) Ping() error {
	if w.IsClosed() {
		return ErrConnectionClosed
	}
	
	w.closeMu.Lock()
	defer w.closeMu.Unlock()
	
	if w.conn == nil {
		return ErrConnectionClosed
	}
	
	w.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return w.conn.WriteMessage(websocket.PingMessage, nil)
}

// Context 返回连接的 context
func (w *WSConn) Context() context.Context {
	return w.ctx
}

// RemoteAddr 返回远程地址
func (w *WSConn) RemoteAddr() net.Addr {
	if w.conn != nil {
		return w.conn.RemoteAddr()
	}
	return nil
}

// LocalAddr 返回本地地址
func (w *WSConn) LocalAddr() net.Addr {
	if w.conn != nil {
		return w.conn.LocalAddr()
	}
	return nil
}

// WriteCh 返回写通道（用于写循环）
func (w *WSConn) WriteCh() <-chan WriteJob {
	return w.writeCh
}

// GetStats 获取统计信息
func (w *WSConn) GetStats() (bytesSent, bytesRecv, packetsSent, packetsRecv int64) {
	return atomic.LoadInt64(&w.bytesSent),
		atomic.LoadInt64(&w.bytesRecv),
		atomic.LoadInt64(&w.packetsSent),
		atomic.LoadInt64(&w.packetsRecv)
}

// AddBytesSent 增加发送字节统计
func (w *WSConn) AddBytesSent(n int64) {
	atomic.AddInt64(&w.bytesSent, n)
}

// AddBytesRecv 增加接收字节统计
func (w *WSConn) AddBytesRecv(n int64) {
	atomic.AddInt64(&w.bytesRecv, n)
}

// AddPacketsSent 增加发送包统计
func (w *WSConn) AddPacketsSent(n int64) {
	atomic.AddInt64(&w.packetsSent, n)
}

// AddPacketsRecv 增加接收包统计
func (w *WSConn) AddPacketsRecv(n int64) {
	atomic.AddInt64(&w.packetsRecv, n)
}

// RawConn 返回底层 WebSocket 连接（谨慎使用）
func (w *WSConn) RawConn() *websocket.Conn {
	return w.conn
}

// ==================== WebSocket 拨号器 ====================

type Dialer struct {
	cfg *config.ClientConfig
}

func NewDialer(cfg *config.ClientConfig) *Dialer {
	return &Dialer{cfg: cfg}
}

func (d *Dialer) Dial(serverURL string, clientID string) (*websocket.Conn, error) {
	return d.DialWithContext(context.Background(), serverURL, clientID)
}

func (d *Dialer) DialWithContext(ctx context.Context, serverURL string, clientID string) (*websocket.Conn, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	// 添加客户端 ID 参数
	q := u.Query()
	q.Set("id", clientID)
	u.RawQuery = q.Encode()

	// 构建 TLS 配置
	tlsConfig, err := d.buildTLSConfig(u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("build TLS config: %w", err)
	}

	dialer := websocket.Dialer{
		TLSClientConfig:   tlsConfig,
		HandshakeTimeout:  10 * time.Second,
		ReadBufferSize:    64 * 1024,
		WriteBufferSize:   64 * 1024,
		EnableCompression: false, // 不启用压缩，避免 CRIME 攻击
	}

	// 设置认证 token
	if d.cfg.Token != "" {
		signedToken := GenerateSignedToken(d.cfg.Token, clientID)
		dialer.Subprotocols = []string{signedToken}
	}

	// 使用 context 进行拨号
	conn, resp, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusUnauthorized:
				return nil, ErrAuthFailed
			case http.StatusServiceUnavailable:
				return nil, errors.New("service unavailable")
			case http.StatusTooManyRequests:
				return nil, errors.New("rate limited")
			}
		}
		return nil, err
	}

	return conn, nil
}

func (d *Dialer) buildTLSConfig(hostname string) (*tls.Config, error) {
	var tlsConfig *tls.Config
	var err error

	if d.cfg.EnableECH && !d.cfg.Insecure {
		tlsConfig, err = ech.BuildTLSConfig(hostname, d.cfg.Insecure)
		if err != nil {
			// ECH 失败时回退到普通 TLS
			tlsConfig = &tls.Config{
				MinVersion:         tls.VersionTLS13,
				ServerName:         hostname,
				InsecureSkipVerify: d.cfg.Insecure,
			}
		}
	} else {
		tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         hostname,
			InsecureSkipVerify: d.cfg.Insecure,
		}
	}

	return tlsConfig, nil
}

// GenerateSignedToken 生成签名的认证令牌
func GenerateSignedToken(secret, clientID string) string {
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%s:%d", clientID, timestamp)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	signature := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s:%d:%s", clientID, timestamp, signature)
}

// ==================== WebSocket 升级器 (服务端) ====================

type Upgrader struct {
	cfg      *config.ServerConfig
	upgrader websocket.Upgrader
}

func NewUpgrader(cfg *config.ServerConfig) *Upgrader {
	return &Upgrader{
		cfg: cfg,
		upgrader: websocket.Upgrader{
			ReadBufferSize:    64 * 1024,
			WriteBufferSize:   64 * 1024,
			EnableCompression: false,
			CheckOrigin:       func(r *http.Request) bool { return true },
			Error: func(w http.ResponseWriter, r *http.Request, status int, reason error) {
				// 自定义错误处理，避免泄露信息
				http.Error(w, http.StatusText(status), status)
			},
		},
	}
}

func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request) (*websocket.Conn, string, error) {
	var clientID string

	// Token 验证
	if u.cfg.Token != "" {
		protocols := websocket.Subprotocols(r)
		valid := false
		for _, p := range protocols {
			if cid, ok := u.validateToken(p); ok {
				valid = true
				clientID = cid
				u.upgrader.Subprotocols = []string{p}
				break
			}
		}
		if !valid {
			return nil, "", errors.New("unauthorized")
		}
	}

	// 升级连接
	conn, err := u.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, "", err
	}

	// 如果没有从 token 获取到客户端 ID，尝试从 URL 参数获取
	if clientID == "" {
		clientID = r.URL.Query().Get("id")
		if clientID == "" {
			clientID = fmt.Sprintf("anon-%s-%d", 
				strings.ReplaceAll(r.RemoteAddr, ":", "-"),
				time.Now().UnixNano()%100000)
		}
	}

	return conn, clientID, nil
}

func (u *Upgrader) validateToken(tokenStr string) (clientID string, valid bool) {
	// 支持简单 token（向后兼容）
	parts := strings.SplitN(tokenStr, ":", 3)

	if len(parts) == 1 {
		// 简单 token 模式
		if tokenStr == u.cfg.Token {
			return "", true
		}
		return "", false
	}

	// 签名 token 模式: clientID:timestamp:signature
	if len(parts) != 3 {
		return "", false
	}

	clientID = parts[0]
	timestampStr := parts[1]
	signature := parts[2]

	// 验证时间戳
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", false
	}

	now := time.Now().Unix()
	if abs(now-timestamp) > TokenValiditySeconds {
		return "", false
	}

	// 验证签名
	message := fmt.Sprintf("%s:%s", clientID, timestampStr)
	mac := hmac.New(sha256.New, []byte(u.cfg.Token))
	mac.Write([]byte(message))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", false
	}

	return clientID, true
}

// ==================== 辅助函数 ====================

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// IsNormalClose 检查是否是正常关闭错误
func IsNormalClose(err error) bool {
	if err == nil {
		return false
	}

	// 检查 WebSocket 关闭错误
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		switch ce.Code {
		case websocket.CloseNormalClosure,
			websocket.CloseGoingAway,
			websocket.CloseNoStatusReceived:
			return true
		}
		return false
	}

	// 检查网络错误
	if errors.Is(err, net.ErrClosed) {
		return true
	}

	// 检查是否是 "use of closed network connection"
	if strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}

	return false
}

// IsTemporaryError 检查是否是临时错误
func IsTemporaryError(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Temporary()
	}
	return false
}

// IsTimeoutError 检查是否是超时错误
func IsTimeoutError(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}


