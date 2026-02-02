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
	utls "github.com/refraction-networking/utls"
	"phantom-x/pkg/config"
	"phantom-x/pkg/metrics"
)

// ==================== 常量定义 ====================

const (
	TokenValiditySeconds  = 300
	DefaultWriteTimeout   = 10 * time.Second
	DefaultReadTimeout    = 60 * time.Second
	DefaultPingInterval   = 30 * time.Second
	DefaultWriteQueueSize = 4096
	CloseGracePeriod      = 5 * time.Second
)

// ==================== 错误定义 ====================

var (
	ErrConnectionClosed  = errors.New("connection closed")
	ErrWriteTimeout      = errors.New("write timeout")
	ErrWriteQueueFull    = errors.New("write queue full")
	ErrConnectionClosing = errors.New("connection closing")
	ErrAuthFailed        = errors.New("authentication failed")
)

// ==================== 写任务 ====================

type WriteJob struct {
	Data     []byte
	Priority bool
	Done     chan error
}

// ==================== WebSocket 拨号器 ====================

type Dialer struct {
	cfg         *config.ClientConfig
	fingerprint utls.ClientHelloID
}

func NewDialer(cfg *config.ClientConfig) *Dialer {
	d := &Dialer{cfg: cfg}
	d.fingerprint = d.getClientHelloID()
	return d
}

func (d *Dialer) getClientHelloID() utls.ClientHelloID {
	switch strings.ToLower(d.cfg.Fingerprint) {
	case "chrome":
		return utls.HelloChrome_Auto
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	case "edge":
		return utls.HelloEdge_Auto
	case "360":
		return utls.Hello360_Auto
	case "qq":
		return utls.HelloQQ_Auto
	case "random":
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}

func (d *Dialer) Dial(serverURL string, clientID string) (*websocket.Conn, error) {
	return d.DialWithContext(context.Background(), serverURL, clientID)
}

func (d *Dialer) DialWithContext(ctx context.Context, serverURL string, clientID string) (*websocket.Conn, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	q := u.Query()
	q.Set("id", clientID)
	u.RawQuery = q.Encode()

	host := u.Hostname()

	dialer := websocket.Dialer{
		HandshakeTimeout:  10 * time.Second,
		ReadBufferSize:    64 * 1024,
		WriteBufferSize:   64 * 1024,
		EnableCompression: false,
	}

	if d.cfg.Token != "" {
		signedToken := GenerateSignedToken(d.cfg.Token, clientID)
		dialer.Subprotocols = []string{signedToken}
	}

	if u.Scheme == "wss" && d.cfg.EnableUTLS && !d.cfg.Insecure {
		dialer.NetDialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.dialWithUTLS(ctx, network, addr, host)
		}
	} else if u.Scheme == "wss" {
		dialer.TLSClientConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: d.cfg.Insecure,
			MinVersion:         tls.VersionTLS12,
		}
	}

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

func (d *Dialer) DialWithOptimalIP(ctx context.Context, serverURL string, clientID string, optimalIP string) (*websocket.Conn, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	q := u.Query()
	q.Set("id", clientID)
	u.RawQuery = q.Encode()

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	dialer := websocket.Dialer{
		HandshakeTimeout:  10 * time.Second,
		ReadBufferSize:    64 * 1024,
		WriteBufferSize:   64 * 1024,
		EnableCompression: false,
	}

	if d.cfg.Token != "" {
		signedToken := GenerateSignedToken(d.cfg.Token, clientID)
		dialer.Subprotocols = []string{signedToken}
	}

	targetAddr := net.JoinHostPort(optimalIP, port)

	dialer.NetDialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.dialWithUTLS(ctx, network, targetAddr, host)
	}

	conn, resp, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return nil, ErrAuthFailed
		}
		return nil, err
	}

	return conn, nil
}

func (d *Dialer) dialWithUTLS(ctx context.Context, network, addr, sni string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("TCP dial: %w", err)
	}

	uConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: d.cfg.Insecure,
		MinVersion:         tls.VersionTLS12,
	}

	uConn := utls.UClient(tcpConn, uConfig, d.fingerprint)

	if err := uConn.HandshakeContext(ctx); err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	return uConn, nil
}

func GenerateSignedToken(secret, clientID string) string {
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%s:%d", clientID, timestamp)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	signature := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s:%d:%s", clientID, timestamp, signature)
}

// ==================== WebSocket 升级器 ====================

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
				http.Error(w, http.StatusText(status), status)
			},
		},
	}
}

func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request) (*websocket.Conn, string, error) {
	var clientID string

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

	conn, err := u.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, "", err
	}

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
	parts := strings.SplitN(tokenStr, ":", 3)

	if len(parts) == 1 {
		if tokenStr == u.cfg.Token {
			return "", true
		}
		return "", false
	}

	if len(parts) != 3 {
		return "", false
	}

	clientID = parts[0]
	timestampStr := parts[1]
	signature := parts[2]

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", false
	}

	now := time.Now().Unix()
	if abs(now-timestamp) > TokenValiditySeconds {
		return "", false
	}

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

func IsNormalClose(err error) bool {
	if err == nil {
		return false
	}

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

	if errors.Is(err, net.ErrClosed) {
		return true
	}

	if strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}

	return false
}

func IsTemporaryError(err error) bool {
	return IsTimeoutError(err)
}

func IsTimeoutError(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

// ==================== WSConn ====================

type WSConn struct {
	ID        int
	conn      *websocket.Conn
	writeCh   chan WriteJob
	closed    int32
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeMu   sync.Mutex

	lastActive int64

	bytesSent   int64
	bytesRecv   int64
	packetsSent int64
	packetsRecv int64

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

func (w *WSConn) SetWriteTimeout(d time.Duration) {
	w.writeTimeout = d
}

func (w *WSConn) SetReadTimeout(d time.Duration) {
	w.readTimeout = d
}

func (w *WSConn) Send(data []byte, priority bool) error {
	if w.IsClosed() {
		return ErrConnectionClosed
	}

	job := WriteJob{
		Data:     data,
		Priority: priority,
	}

	if priority {
		select {
		case w.writeCh <- job:
			return nil
		default:
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

	select {
	case w.writeCh <- job:
	case <-time.After(timeout):
		return ErrWriteQueueFull
	case <-w.ctx.Done():
		return ErrConnectionClosing
	}

	select {
	case err := <-job.Done:
		return err
	case <-time.After(timeout):
		return ErrWriteTimeout
	case <-w.ctx.Done():
		return ErrConnectionClosing
	}
}

func (w *WSConn) Close() {
	w.closeOnce.Do(func() {
		atomic.StoreInt32(&w.closed, 1)

		w.cancel()

		if w.conn != nil {
			_ = w.conn.SetWriteDeadline(time.Now().Add(CloseGracePeriod))
			_ = w.conn.WriteMessage(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			)
			_ = w.conn.Close()
		}

		w.drainWriteChannel()
	})
}

func (w *WSConn) drainWriteChannel() {
	// 使用 len() 检查避免 SA4011
	for len(w.writeCh) > 0 {
		job := <-w.writeCh
		if job.Done != nil {
			select {
			case job.Done <- ErrConnectionClosed:
			default:
			}
		}
	}
}

func (w *WSConn) IsClosed() bool {
	return atomic.LoadInt32(&w.closed) == 1
}

func (w *WSConn) UpdateActive() {
	atomic.StoreInt64(&w.lastActive, time.Now().UnixNano())
}

func (w *WSConn) GetLastActive() time.Time {
	return time.Unix(0, atomic.LoadInt64(&w.lastActive))
}

func (w *WSConn) IdleDuration() time.Duration {
	return time.Since(w.GetLastActive())
}

func (w *WSConn) WriteMessage(msgType int, data []byte) error {
	if w.IsClosed() {
		return ErrConnectionClosed
	}

	w.closeMu.Lock()
	defer w.closeMu.Unlock()

	if w.conn == nil {
		return ErrConnectionClosed
	}

	if err := w.conn.SetWriteDeadline(time.Now().Add(w.writeTimeout)); err != nil {
		return err
	}
	err := w.conn.WriteMessage(msgType, data)
	if err == nil {
		atomic.AddInt64(&w.bytesSent, int64(len(data)))
		atomic.AddInt64(&w.packetsSent, 1)
		w.UpdateActive()
	}
	return err
}

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

func (w *WSConn) SetReadDeadline(t time.Time) error {
	if w.conn == nil {
		return ErrConnectionClosed
	}
	return w.conn.SetReadDeadline(t)
}

func (w *WSConn) SetWriteDeadline(t time.Time) error {
	if w.conn == nil {
		return ErrConnectionClosed
	}
	return w.conn.SetWriteDeadline(t)
}

func (w *WSConn) SetPongHandler(h func(string) error) {
	if w.conn != nil {
		w.conn.SetPongHandler(h)
	}
}

func (w *WSConn) SetPingHandler(h func(string) error) {
	if w.conn != nil {
		w.conn.SetPingHandler(h)
	}
}

func (w *WSConn) Ping() error {
	if w.IsClosed() {
		return ErrConnectionClosed
	}

	w.closeMu.Lock()
	defer w.closeMu.Unlock()

	if w.conn == nil {
		return ErrConnectionClosed
	}

	if err := w.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	return w.conn.WriteMessage(websocket.PingMessage, nil)
}

func (w *WSConn) Context() context.Context {
	return w.ctx
}

func (w *WSConn) RemoteAddr() net.Addr {
	if w.conn != nil {
		return w.conn.RemoteAddr()
	}
	return nil
}

func (w *WSConn) LocalAddr() net.Addr {
	if w.conn != nil {
		return w.conn.LocalAddr()
	}
	return nil
}

func (w *WSConn) WriteCh() <-chan WriteJob {
	return w.writeCh
}

func (w *WSConn) GetStats() (bytesSent, bytesRecv, packetsSent, packetsRecv int64) {
	return atomic.LoadInt64(&w.bytesSent),
		atomic.LoadInt64(&w.bytesRecv),
		atomic.LoadInt64(&w.packetsSent),
		atomic.LoadInt64(&w.packetsRecv)
}

func (w *WSConn) AddBytesSent(n int64) {
	atomic.AddInt64(&w.bytesSent, n)
}

func (w *WSConn) AddBytesRecv(n int64) {
	atomic.AddInt64(&w.bytesRecv, n)
}

func (w *WSConn) AddPacketsSent(n int64) {
	atomic.AddInt64(&w.packetsSent, n)
}

func (w *WSConn) AddPacketsRecv(n int64) {
	atomic.AddInt64(&w.packetsRecv, n)
}

func (w *WSConn) RawConn() *websocket.Conn {
	return w.conn
}
