

//internal/pool/connpool.go
package pool

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"phantom-x/internal/proto"
	"phantom-x/internal/transport"
	"phantom-x/pkg/config"
	plog "phantom-x/pkg/log"
	"phantom-x/pkg/metrics"
)

// ==================== 错误定义 ====================

var (
	ErrPoolClosed      = errors.New("connection pool closed")
	ErrConnClosed      = errors.New("connection closed")
	ErrSendTimeout     = errors.New("send timeout")
	ErrWriteTimeout    = errors.New("write timeout")
	ErrNoAvailableConn = errors.New("no available connection")
	ErrQueueFull       = errors.New("write queue full")
)

// ==================== 常量定义 ====================

const (
	DefaultNumConnections   = 3
	DefaultWriteQueueSize   = 4096
	DefaultWriteTimeout     = 10 * time.Second
	DefaultReadTimeout      = 60 * time.Second
	DefaultPingInterval     = 30 * time.Second
	DefaultReconnectDelay   = time.Second
	DefaultMaxBackoff       = 30 * time.Second
	DefaultAggregateDelay   = 5 * time.Millisecond
	DefaultMaxAggSize       = 64 * 1024
	DefaultSendTimeout      = 5 * time.Second
	AggFlushThreshold       = 0.8
	MaxPooledItemsCap       = 64
)

// ==================== 对象池 ====================

var aggregatedDataPool = sync.Pool{
	New: func() any {
		return &proto.AggregatedData{
			Items: make([]struct {
				StreamID uint32
				Data     []byte
			}, 0, 16),
		}
	},
}

func getAggregatedData() *proto.AggregatedData {
	return aggregatedDataPool.Get().(*proto.AggregatedData)
}

func putAggregatedData(agg *proto.AggregatedData) {
	if agg == nil {
		return
	}

	if cap(agg.Items) > MaxPooledItemsCap {
		return
	}

	for i := range agg.Items {
		agg.Items[i].StreamID = 0
		agg.Items[i].Data = nil
	}
	agg.Items = agg.Items[:0]
	aggregatedDataPool.Put(agg)
}

// ==================== 配置 ====================

type Config struct {
	ServerURL      string
	Token          string
	ClientID       string
	Insecure       bool
	NumConnections int
	WriteQueueSize int
	WriteTimeout   time.Duration
	ReadTimeout    time.Duration
	PingInterval   time.Duration
	ReconnectDelay time.Duration
	MaxBackoff     time.Duration

	EnableECH bool
	ECHDomain string
	ECHDns    string

	EnablePadding     bool
	PaddingMinSize    int
	PaddingMaxSize    int
	PaddingDistribute string

	AggregateDelay time.Duration
	MaxAggSize     int
}

func (c *Config) Validate() {
	if c.NumConnections <= 0 {
		c.NumConnections = DefaultNumConnections
	}
	if c.NumConnections > 10 {
		c.NumConnections = 10
	}
	if c.WriteQueueSize <= 0 {
		c.WriteQueueSize = DefaultWriteQueueSize
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = DefaultWriteTimeout
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = DefaultReadTimeout
	}
	if c.PingInterval <= 0 {
		c.PingInterval = DefaultPingInterval
	}
	if c.ReconnectDelay <= 0 {
		c.ReconnectDelay = DefaultReconnectDelay
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = DefaultMaxBackoff
	}
	if c.AggregateDelay <= 0 {
		c.AggregateDelay = DefaultAggregateDelay
	}
	if c.MaxAggSize <= 0 {
		c.MaxAggSize = DefaultMaxAggSize
	}
}

// ==================== 连接池 ====================

type ConnPool struct {
	cfg          *Config
	dialer       *transport.Dialer
	conns        []*PoolConn
	connsMu      sync.RWMutex
	frameHandler func(connID int, streamID uint32, cmd byte, payload []byte)
	running      int32
	stopCh       chan struct{}
	wg           sync.WaitGroup
	nextConnIdx  uint32
}

type PoolConn struct {
	ID          int
	conn        *websocket.Conn
	pool        *ConnPool
	writeCh     chan transport.WriteJob
	paddingCalc *proto.PaddingCalculator
	ctx         context.Context
	cancel      context.CancelFunc
	closeOnce   sync.Once
	closed      int32

	bytesSent   int64
	bytesRecv   int64
	packetsSent int64
	packetsRecv int64
}

func NewConnPool(cfg *Config) *ConnPool {
	cfg.Validate()

	clientCfg := &config.ClientConfig{
		Server:    cfg.ServerURL,
		Token:     cfg.Token,
		ClientID:  cfg.ClientID,
		Insecure:  cfg.Insecure,
		EnableECH: cfg.EnableECH,
		ECHDomain: cfg.ECHDomain,
		ECHDns:    cfg.ECHDns,
	}

	return &ConnPool{
		cfg:    cfg,
		dialer: transport.NewDialer(clientCfg),
		conns:  make([]*PoolConn, cfg.NumConnections),
		stopCh: make(chan struct{}),
	}
}

func (p *ConnPool) SetFrameHandler(handler func(connID int, streamID uint32, cmd byte, payload []byte)) {
	p.frameHandler = handler
}

func (p *ConnPool) Start() error {
	if !atomic.CompareAndSwapInt32(&p.running, 0, 1) {
		return nil
	}

	for i := 0; i < p.cfg.NumConnections; i++ {
		p.wg.Add(1)
		go p.maintainConnection(i)
	}

	return nil
}

func (p *ConnPool) Stop() {
	if !atomic.CompareAndSwapInt32(&p.running, 1, 0) {
		return
	}
	close(p.stopCh)
	p.wg.Wait()
}

func (p *ConnPool) IsRunning() bool {
	return atomic.LoadInt32(&p.running) == 1
}

func (p *ConnPool) maintainConnection(id int) {
	defer p.wg.Done()

	backoff := p.cfg.ReconnectDelay

	for {
		select {
		case <-p.stopCh:
			return
		default:
		}

		conn, err := p.dialer.Dial(p.cfg.ServerURL, p.cfg.ClientID)
		if err != nil {
			plog.Debug("[Pool] Connection %d dial failed: %v", id, err)
			metrics.IncrConnectError()

			select {
			case <-p.stopCh:
				return
			case <-time.After(backoff):
			}

			backoff = backoff * 2
			if backoff > p.cfg.MaxBackoff {
				backoff = p.cfg.MaxBackoff
			}
			continue
		}

		backoff = p.cfg.ReconnectDelay
		plog.Info("[Pool] Connection %d established", id)
		metrics.IncrActiveConnections()

		ctx, cancel := context.WithCancel(context.Background())

		var paddingCalc *proto.PaddingCalculator
		if p.cfg.EnablePadding {
			paddingCalc = proto.NewPaddingCalculator(&proto.PaddingConfig{
				Enabled:      true,
				MinSize:      p.cfg.PaddingMinSize,
				MaxPadding:   p.cfg.PaddingMaxSize,
				Distribution: p.cfg.PaddingDistribute,
			})
		}

		poolConn := &PoolConn{
			ID:          id,
			conn:        conn,
			pool:        p,
			writeCh:     make(chan transport.WriteJob, p.cfg.WriteQueueSize),
			paddingCalc: paddingCalc,
			ctx:         ctx,
			cancel:      cancel,
		}

		p.connsMu.Lock()
		p.conns[id] = poolConn
		p.connsMu.Unlock()

		poolConn.serve()

		p.connsMu.Lock()
		p.conns[id] = nil
		p.connsMu.Unlock()

		conn.Close()
		metrics.DecrActiveConnections()
		metrics.IncrReconnectCount()
		plog.Info("[Pool] Connection %d closed, reconnecting...", id)
	}
}

func (w *PoolConn) serve() {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		w.writeLoop()
	}()

	w.readLoop()

	w.cancel()
	wg.Wait()
}

func (w *PoolConn) writeLoop() {
	cfg := w.pool.cfg
	maxAggSize := cfg.MaxAggSize
	aggDelay := cfg.AggregateDelay
	flushThreshold := int(float64(maxAggSize) * AggFlushThreshold)

	pendingData := make(map[uint32][]byte)
	pendingSize := 0

	flushTimer := time.NewTimer(aggDelay)
	if !flushTimer.Stop() {
		select {
		case <-flushTimer.C:
		default:
		}
	}
	timerActive := false
	defer flushTimer.Stop()

	sendBuf := make([]byte, maxAggSize+proto.MaxPadding+proto.HeaderLen+1)

	pingTicker := time.NewTicker(cfg.PingInterval)
	defer pingTicker.Stop()

	flush := func() {
		if timerActive {
			if !flushTimer.Stop() {
				select {
				case <-flushTimer.C:
				default:
				}
			}
			timerActive = false
		}

		if len(pendingData) == 0 {
			return
		}

		agg := getAggregatedData()

		for sid, data := range pendingData {
			agg.Items = append(agg.Items, struct {
				StreamID uint32
				Data     []byte
			}{sid, data})
		}

		var frameLen int

		if len(agg.Items) == 1 {
			item := agg.Items[0]
			frameLen = proto.PackFrameWithPadding(
				sendBuf,
				proto.CmdData,
				item.StreamID,
				0,
				item.Data,
				w.paddingCalc,
			)
		} else {
			aggData := agg.Encode()
			frameLen = proto.PackFrameWithPadding(
				sendBuf,
				proto.CmdData,
				0,
				proto.FlagAggregate,
				aggData,
				w.paddingCalc,
			)
		}

		putAggregatedData(agg)

		if err := w.conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout)); err != nil {
			w.cancel()
			return
		}
		if err := w.conn.WriteMessage(websocket.BinaryMessage, sendBuf[:frameLen]); err != nil {
			plog.Debug("[Pool] Write error on conn %d: %v", w.ID, err)
			w.cancel()
			return
		}

		atomic.AddInt64(&w.packetsSent, int64(len(pendingData)))
		atomic.AddInt64(&w.bytesSent, int64(frameLen))
		metrics.IncrPacketsSent(int64(len(pendingData)))
		metrics.AddBytesSent(int64(frameLen))

		for k := range pendingData {
			delete(pendingData, k)
		}
		pendingSize = 0
	}

	defer func() {
		flush()

		for {
			select {
			case job, ok := <-w.writeCh:
				if !ok {
					return
				}
				if job.Done != nil {
					select {
					case job.Done <- ErrConnClosed:
					default:
					}
				}
			default:
				return
			}
		}
	}()

	for {
		select {
		case <-w.ctx.Done():
			return

		case job, ok := <-w.writeCh:
			if !ok {
				return
			}

			if len(job.Data) >= proto.HeaderLen {
				cmd, sid, flags, length := proto.UnpackHeader(job.Data[:proto.HeaderLen])

				if cmd == proto.CmdData && !job.Priority && flags&proto.FlagAggregate == 0 {
					payloadEnd := proto.HeaderLen + length
					if payloadEnd > len(job.Data) {
						payloadEnd = len(job.Data)
					}
					payload := job.Data[proto.HeaderLen:payloadEnd]
					payloadLen := len(payload)

					if pendingSize > 0 && payloadLen > maxAggSize/2 {
						flush()
					}

					if existing, ok := pendingData[sid]; ok {
						pendingData[sid] = append(existing, payload...)
					} else {
						dataCopy := make([]byte, payloadLen)
						copy(dataCopy, payload)
						pendingData[sid] = dataCopy
					}
					pendingSize += payloadLen

					if !timerActive {
						flushTimer.Reset(aggDelay)
						timerActive = true
					}

					if pendingSize >= flushThreshold {
						flush()
					}

					if job.Done != nil {
						select {
						case job.Done <- nil:
						default:
						}
					}
					continue
				}
			}

			flush()

			if w.paddingCalc != nil && len(job.Data) >= proto.HeaderLen {
				cmd, sid, flags, length := proto.UnpackHeader(job.Data[:proto.HeaderLen])
				payloadEnd := proto.HeaderLen + length
				if payloadEnd > len(job.Data) {
					payloadEnd = len(job.Data)
				}
				payload := job.Data[proto.HeaderLen:payloadEnd]

				frameLen := proto.PackFrameWithPadding(
					sendBuf,
					cmd,
					sid,
					flags,
					payload,
					w.paddingCalc,
				)

				if err := w.conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout)); err != nil {
					if job.Done != nil {
						select {
						case job.Done <- err:
						default:
						}
					}
					w.cancel()
					return
				}
				if err := w.conn.WriteMessage(websocket.BinaryMessage, sendBuf[:frameLen]); err != nil {
					plog.Debug("[Pool] Write error on conn %d: %v", w.ID, err)
					if job.Done != nil {
						select {
						case job.Done <- err:
						default:
						}
					}
					w.cancel()
					return
				}

				atomic.AddInt64(&w.packetsSent, 1)
				atomic.AddInt64(&w.bytesSent, int64(frameLen))
				metrics.IncrPacketsSent(1)
				metrics.AddBytesSent(int64(frameLen))
			} else {
				if err := w.conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout)); err != nil {
					if job.Done != nil {
						select {
						case job.Done <- err:
						default:
						}
					}
					w.cancel()
					return
				}
				if err := w.conn.WriteMessage(websocket.BinaryMessage, job.Data); err != nil {
					plog.Debug("[Pool] Write error on conn %d: %v", w.ID, err)
					if job.Done != nil {
						select {
						case job.Done <- err:
						default:
						}
					}
					w.cancel()
					return
				}

				atomic.AddInt64(&w.packetsSent, 1)
				atomic.AddInt64(&w.bytesSent, int64(len(job.Data)))
				metrics.IncrPacketsSent(1)
				metrics.AddBytesSent(int64(len(job.Data)))
			}

			if job.Done != nil {
				select {
				case job.Done <- nil:
				default:
				}
			}

		case <-flushTimer.C:
			timerActive = false
			flush()

		case <-pingTicker.C:
			if err := w.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				w.cancel()
				return
			}
			if err := w.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				plog.Debug("[Pool] Ping error on conn %d: %v", w.ID, err)
				w.cancel()
				return
			}
		}
	}
}

func (w *PoolConn) readLoop() {
	cfg := w.pool.cfg

	w.conn.SetPongHandler(func(string) error {
		return w.conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
	})

	for {
		select {
		case <-w.ctx.Done():
			return
		default:
		}

		if err := w.conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout)); err != nil {
			w.cancel()
			return
		}
		mt, data, err := w.conn.ReadMessage()
		if err != nil {
			if !transport.IsNormalClose(err) {
				plog.Debug("[Pool] Read error on conn %d: %v", w.ID, err)
			}
			w.cancel()
			return
		}

		if mt != websocket.BinaryMessage || len(data) < proto.HeaderLen {
			continue
		}

		atomic.AddInt64(&w.packetsRecv, 1)
		atomic.AddInt64(&w.bytesRecv, int64(len(data)))
		metrics.IncrPacketsRecv(1)
		metrics.AddBytesRecv(int64(len(data)))

		cmd, streamID, flags, length := proto.UnpackHeader(data[:proto.HeaderLen])

		payloadEnd := proto.HeaderLen + length
		if payloadEnd > len(data) {
			continue
		}
		payload := data[proto.HeaderLen:payloadEnd]

		if flags&proto.FlagPadding != 0 {
			payload = proto.RemovePadding(payload)
		}

		if flags&proto.FlagAggregate != 0 {
			agg, err := proto.DecodeAggregatedData(payload)
			if err != nil {
				continue
			}
			for _, item := range agg.Items {
				if w.pool.frameHandler != nil {
					w.pool.frameHandler(w.ID, item.StreamID, cmd, item.Data)
				}
			}
			continue
		}

		if w.pool.frameHandler != nil {
			w.pool.frameHandler(w.ID, streamID, cmd, payload)
		}
	}
}

func (w *PoolConn) Close() {
	w.closeOnce.Do(func() {
		atomic.StoreInt32(&w.closed, 1)
		w.cancel()

		_ = w.conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second),
		)

		w.conn.Close()
	})
}

func (w *PoolConn) IsClosed() bool {
	return atomic.LoadInt32(&w.closed) == 1
}

func (w *PoolConn) Send(data []byte) error {
	if w.IsClosed() {
		return ErrConnClosed
	}

	select {
	case w.writeCh <- transport.WriteJob{Data: data}:
		return nil
	case <-time.After(DefaultSendTimeout):
		metrics.IncrWriteTimeout()
		return ErrSendTimeout
	case <-w.ctx.Done():
		return ErrConnClosed
	}
}

func (w *PoolConn) SendPriority(data []byte) error {
	if w.IsClosed() {
		return ErrConnClosed
	}

	select {
	case w.writeCh <- transport.WriteJob{Data: data, Priority: true}:
		return nil
	case <-time.After(DefaultSendTimeout):
		metrics.IncrWriteTimeout()
		return ErrSendTimeout
	case <-w.ctx.Done():
		return ErrConnClosed
	}
}

func (w *PoolConn) SendSync(data []byte, timeout time.Duration) error {
	if w.IsClosed() {
		return ErrConnClosed
	}

	done := make(chan error, 1)
	job := transport.WriteJob{
		Data:     data,
		Priority: true,
		Done:     done,
	}

	select {
	case w.writeCh <- job:
	case <-time.After(timeout):
		return ErrQueueFull
	case <-w.ctx.Done():
		return ErrConnClosed
	}

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return ErrWriteTimeout
	case <-w.ctx.Done():
		return ErrConnClosed
	}
}

func (w *PoolConn) Stats() (bytesSent, bytesRecv, packetsSent, packetsRecv int64) {
	return atomic.LoadInt64(&w.bytesSent),
		atomic.LoadInt64(&w.bytesRecv),
		atomic.LoadInt64(&w.packetsSent),
		atomic.LoadInt64(&w.packetsRecv)
}

// ==================== 连接池方法 ====================

func (p *ConnPool) selectConnection() *PoolConn {
	p.connsMu.RLock()
	defer p.connsMu.RUnlock()

	numConns := len(p.conns)
	if numConns == 0 {
		return nil
	}

	startIdx := atomic.AddUint32(&p.nextConnIdx, 1) % uint32(numConns)

	for i := 0; i < numConns; i++ {
		idx := (int(startIdx) + i) % numConns
		if conn := p.conns[idx]; conn != nil && !conn.IsClosed() {
			return conn
		}
	}

	return nil
}

func (p *ConnPool) SendTo(connID int, data []byte) error {
	if !p.IsRunning() {
		return ErrPoolClosed
	}

	p.connsMu.RLock()
	if connID >= 0 && connID < len(p.conns) && p.conns[connID] != nil {
		conn := p.conns[connID]
		p.connsMu.RUnlock()
		return conn.Send(data)
	}
	p.connsMu.RUnlock()

	return p.Broadcast(data)
}

func (p *ConnPool) Broadcast(data []byte) error {
	if !p.IsRunning() {
		return ErrPoolClosed
	}

	conn := p.selectConnection()
	if conn == nil {
		return ErrNoAvailableConn
	}
	return conn.Send(data)
}

func (p *ConnPool) BroadcastAll(data []byte) {
	if !p.IsRunning() {
		return
	}

	p.connsMu.RLock()
	defer p.connsMu.RUnlock()

	for _, conn := range p.conns {
		if conn != nil && !conn.IsClosed() {
			_ = conn.Send(data)
		}
	}
}

func (p *ConnPool) GetActiveCount() int {
	p.connsMu.RLock()
	defer p.connsMu.RUnlock()

	count := 0
	for _, conn := range p.conns {
		if conn != nil && !conn.IsClosed() {
			count++
		}
	}
	return count
}

func (p *ConnPool) GetTotalStats() (bytesSent, bytesRecv, packetsSent, packetsRecv int64) {
	p.connsMu.RLock()
	defer p.connsMu.RUnlock()

	for _, conn := range p.conns {
		if conn != nil {
			bs, br, ps, pr := conn.Stats()
			bytesSent += bs
			bytesRecv += br
			packetsSent += ps
			packetsRecv += pr
		}
	}
	return
}



