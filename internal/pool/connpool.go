

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
	AggFlushThreshold       = 0.8 // 80% 时触发刷新
	MaxPooledItemsCap       = 64  // 对象池中保留的最大 Items 容量
)

// ==================== 对象池 ====================

// aggregatedDataPool 用于复用 AggregatedData 对象，减少高吞吐量场景下的 GC 压力
var aggregatedDataPool = sync.Pool{
	New: func() any {
		return &proto.AggregatedData{
			Items: make([]struct {
				StreamID uint32
				Data     []byte
			}, 0, 16), // 预分配 16 个 item 的容量
		}
	},
}

// getAggregatedData 从对象池获取 AggregatedData
func getAggregatedData() *proto.AggregatedData {
	return aggregatedDataPool.Get().(*proto.AggregatedData)
}

// putAggregatedData 将 AggregatedData 归还到对象池
// 注意：归还前会清空 Items 切片，但保留底层容量
// 如果容量过大，则不归还，让 GC 回收以避免内存潮汐
func putAggregatedData(agg *proto.AggregatedData) {
	if agg == nil {
		return
	}

	// 如果容量超过阈值，不归还到池中，让 GC 回收
	// 这样可以避免内存使用量随时间推移锁定在高位
	if cap(agg.Items) > MaxPooledItemsCap {
		return
	}

	// 清空切片内容，但保留容量以便复用
	// 同时清除对 Data 切片的引用，避免内存泄漏
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

	// ECH 配置
	EnableECH bool
	ECHDomain string
	ECHDns    string

	// Padding 配置
	EnablePadding     bool
	PaddingMinSize    int
	PaddingMaxSize    int
	PaddingDistribute string

	// 聚合配置
	AggregateDelay time.Duration
	MaxAggSize     int
}

// Validate 验证并填充默认配置
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
	nextConnIdx  uint32 // 用于轮询选择连接
}

// PoolConn 连接包装
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
	mu          sync.RWMutex

	// 统计信息
	bytesSent   int64
	bytesRecv   int64
	packetsSent int64
	packetsRecv int64
}

// NewConnPool 创建连接池
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

// SetFrameHandler 设置帧处理回调
func (p *ConnPool) SetFrameHandler(handler func(connID int, streamID uint32, cmd byte, payload []byte)) {
	p.frameHandler = handler
}

// Start 启动连接池
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

// Stop 停止连接池
func (p *ConnPool) Stop() {
	if !atomic.CompareAndSwapInt32(&p.running, 1, 0) {
		return
	}
	close(p.stopCh)
	p.wg.Wait()
}

// IsRunning 检查是否运行中
func (p *ConnPool) IsRunning() bool {
	return atomic.LoadInt32(&p.running) == 1
}

// maintainConnection 维护单个连接
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

			// 指数退避
			backoff = backoff * 2
			if backoff > p.cfg.MaxBackoff {
				backoff = p.cfg.MaxBackoff
			}
			continue
		}

		// 连接成功，重置退避
		backoff = p.cfg.ReconnectDelay
		plog.Info("[Pool] Connection %d established", id)
		metrics.IncrActiveConnections()

		// 创建连接包装
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

		// 注册连接
		p.connsMu.Lock()
		p.conns[id] = poolConn
		p.connsMu.Unlock()

		// 运行连接
		poolConn.serve()

		// 连接关闭，清理
		p.connsMu.Lock()
		p.conns[id] = nil
		p.connsMu.Unlock()

		conn.Close()
		metrics.DecrActiveConnections()
		metrics.IncrReconnectCount()
		plog.Info("[Pool] Connection %d closed, reconnecting...", id)
	}
}

// serve 运行连接的读写循环
func (w *PoolConn) serve() {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		w.writeLoop()
	}()

	w.readLoop()

	// 等待写循环结束
	w.cancel()
	wg.Wait()
}

// writeLoop 写循环
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

	// 刷新函数
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

		// 从对象池获取 AggregatedData
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

		// 归还到对象池（在发送前归还，因为数据已编码到 sendBuf）
		putAggregatedData(agg)

		w.conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
		if err := w.conn.WriteMessage(websocket.BinaryMessage, sendBuf[:frameLen]); err != nil {
			plog.Debug("[Pool] Write error on conn %d: %v", w.ID, err)
			w.cancel()
			return
		}

		atomic.AddInt64(&w.packetsSent, int64(len(pendingData)))
		atomic.AddInt64(&w.bytesSent, int64(frameLen))
		metrics.IncrPacketsSent(int64(len(pendingData)))
		metrics.AddBytesSent(int64(frameLen))

		// 清空 pending 数据
		for k := range pendingData {
			delete(pendingData, k)
		}
		pendingSize = 0
	}

	// 退出时确保发送所有剩余数据并通知等待的任务
	defer func() {
		// 刷新剩余的聚合数据
		flush()

		// 排空写队列并通知失败
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

			// 解析帧头判断是否可以聚合
			if len(job.Data) >= proto.HeaderLen {
				cmd, sid, flags, length := proto.UnpackHeader(job.Data[:proto.HeaderLen])

				// 只有非优先级的数据帧才进行聚合
				if cmd == proto.CmdData && !job.Priority && flags&proto.FlagAggregate == 0 {
					payloadEnd := proto.HeaderLen + length
					if payloadEnd > len(job.Data) {
						payloadEnd = len(job.Data)
					}
					payload := job.Data[proto.HeaderLen:payloadEnd]
					payloadLen := len(payload)

					// 如果单个流数据过大，先刷新
					if pendingSize > 0 && payloadLen > maxAggSize/2 {
						flush()
					}

					// 合并同流数据
					if existing, ok := pendingData[sid]; ok {
						pendingData[sid] = append(existing, payload...)
					} else {
						dataCopy := make([]byte, payloadLen)
						copy(dataCopy, payload)
						pendingData[sid] = dataCopy
					}
					pendingSize += payloadLen

					// 启动定时器
					if !timerActive {
						flushTimer.Reset(aggDelay)
						timerActive = true
					}

					// 达到阈值时立即刷新
					if pendingSize >= flushThreshold {
						flush()
					}

					// 通知成功
					if job.Done != nil {
						select {
						case job.Done <- nil:
						default:
						}
					}
					continue
				}
			}

			// 非聚合帧：先刷新聚合数据，再发送
			flush()

			// 应用 padding
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

				w.conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
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
				// 直接发送
				w.conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
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

			// 通知完成
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
			w.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := w.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				plog.Debug("[Pool] Ping error on conn %d: %v", w.ID, err)
				w.cancel()
				return
			}
		}
	}
}

// readLoop 读循环
func (w *PoolConn) readLoop() {
	cfg := w.pool.cfg

	w.conn.SetPongHandler(func(string) error {
		w.conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
		return nil
	})

	for {
		select {
		case <-w.ctx.Done():
			return
		default:
		}

		w.conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
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

		// 解析帧
		cmd, streamID, flags, length := proto.UnpackHeader(data[:proto.HeaderLen])

		payloadEnd := proto.HeaderLen + length
		if payloadEnd > len(data) {
			continue
		}
		payload := data[proto.HeaderLen:payloadEnd]

		// 移除 padding
		if flags&proto.FlagPadding != 0 {
			payload = proto.RemovePadding(payload)
		}

		// 处理聚合包
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

		// 回调处理
		if w.pool.frameHandler != nil {
			w.pool.frameHandler(w.ID, streamID, cmd, payload)
		}
	}
}

// Close 关闭连接
func (w *PoolConn) Close() {
	w.closeOnce.Do(func() {
		atomic.StoreInt32(&w.closed, 1)
		w.cancel()

		// 发送关闭帧
		w.conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second),
		)

		w.conn.Close()
	})
}

// IsClosed 检查是否已关闭
func (w *PoolConn) IsClosed() bool {
	return atomic.LoadInt32(&w.closed) == 1
}

// Send 发送数据（异步）
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

// SendPriority 发送优先数据（异步）
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

// SendSync 同步发送数据
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

// Stats 返回连接统计信息
func (w *PoolConn) Stats() (bytesSent, bytesRecv, packetsSent, packetsRecv int64) {
	return atomic.LoadInt64(&w.bytesSent),
		atomic.LoadInt64(&w.bytesRecv),
		atomic.LoadInt64(&w.packetsSent),
		atomic.LoadInt64(&w.packetsRecv)
}

// ==================== 连接池方法 ====================

// selectConnection 轮询选择一个可用连接
func (p *ConnPool) selectConnection() *PoolConn {
	p.connsMu.RLock()
	defer p.connsMu.RUnlock()

	numConns := len(p.conns)
	if numConns == 0 {
		return nil
	}

	// 轮询从上次位置开始
	startIdx := atomic.AddUint32(&p.nextConnIdx, 1) % uint32(numConns)

	for i := 0; i < numConns; i++ {
		idx := (int(startIdx) + i) % numConns
		if conn := p.conns[idx]; conn != nil && !conn.IsClosed() {
			return conn
		}
	}

	return nil
}

// SendTo 发送到指定连接
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

	// 回退到广播
	return p.Broadcast(data)
}

// Broadcast 广播到第一个可用连接
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

// BroadcastAll 广播到所有连接
func (p *ConnPool) BroadcastAll(data []byte) {
	if !p.IsRunning() {
		return
	}

	p.connsMu.RLock()
	defer p.connsMu.RUnlock()

	for _, conn := range p.conns {
		if conn != nil && !conn.IsClosed() {
			conn.Send(data)
		}
	}
}

// GetActiveCount 获取活跃连接数
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

// GetTotalStats 获取所有连接的统计信息
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

// ==================== 辅助函数 ====================

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

