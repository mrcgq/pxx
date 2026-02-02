package stream

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"phantom-x/pkg/metrics"
)

// ==================== 流状态 ====================

type State int32

const (
	StateInit State = iota
	StateConnecting
	StateConnected
	StateClosed
)

// ==================== 流定义 ====================

type Stream struct {
	ID        uint32
	Target    string
	IsUDP     bool
	State     int32
	connID    int32
	CreatedAt time.Time

	// TCP 连接
	TCPConn net.Conn

	// UDP 关联
	UDPConn       *net.UDPConn
	UDPAddr       *net.UDPAddr
	UDPClientAddr *net.UDPAddr

	// 数据通道
	DataCh    chan []byte
	Connected chan bool
	CloseCh   chan struct{}

	// 回调
	OnClose func(id uint32)

	mu        sync.RWMutex
	closeOnce sync.Once
}

func NewStream(id uint32, target string, isUDP bool) *Stream {
	return &Stream{
		ID:        id,
		Target:    target,
		IsUDP:     isUDP,
		State:     int32(StateInit),
		connID:    -1,
		CreatedAt: time.Now(),
		DataCh:    make(chan []byte, 64),
		Connected: make(chan bool, 1),
		CloseCh:   make(chan struct{}),
	}
}

// SetConnID 设置绑定的连接 ID（线程安全）
func (s *Stream) SetConnID(id int) {
	atomic.StoreInt32(&s.connID, int32(id))
}

// GetConnID 获取绑定的连接 ID（线程安全）
func (s *Stream) GetConnID() int {
	return int(atomic.LoadInt32(&s.connID))
}

func (s *Stream) SetState(state State) {
	atomic.StoreInt32(&s.State, int32(state))
}

func (s *Stream) GetState() State {
	return State(atomic.LoadInt32(&s.State))
}

func (s *Stream) IsClosed() bool {
	return s.GetState() == StateClosed
}

func (s *Stream) Close() {
	s.closeOnce.Do(func() {
		atomic.StoreInt32(&s.State, int32(StateClosed))

		close(s.CloseCh)

		s.mu.Lock()
		if s.TCPConn != nil {
			_ = s.TCPConn.Close()
		}
		if s.UDPConn != nil {
			_ = s.UDPConn.Close()
		}
		s.mu.Unlock()

		// 排空数据通道 - 使用标签化的 break
	drainLoop:
		for {
			select {
			case <-s.DataCh:
			default:
				break drainLoop
			}
		}

		if s.OnClose != nil {
			s.OnClose(s.ID)
		}

		metrics.DecrActiveStreams()
	})
}

func (s *Stream) Write(data []byte) (int, error) {
	if s.IsClosed() {
		return 0, errors.New("stream closed")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.IsUDP && s.UDPConn != nil && s.UDPAddr != nil {
		return s.UDPConn.WriteToUDP(data, s.UDPAddr)
	}

	if s.TCPConn != nil {
		if err := s.TCPConn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return 0, err
		}
		n, err := s.TCPConn.Write(data)
		_ = s.TCPConn.SetWriteDeadline(time.Time{})
		return n, err
	}

	return 0, errors.New("no connection")
}

func (s *Stream) Read(buf []byte) (int, error) {
	if s.IsClosed() {
		return 0, io.EOF
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.TCPConn != nil {
		return s.TCPConn.Read(buf)
	}

	return 0, errors.New("no connection")
}

func (s *Stream) SendData(data []byte) error {
	if s.IsClosed() {
		return errors.New("stream closed")
	}

	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	select {
	case s.DataCh <- dataCopy:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("data channel blocked")
	case <-s.CloseCh:
		return errors.New("stream closed")
	}
}

func (s *Stream) SignalConnected() {
	select {
	case s.Connected <- true:
	default:
	}
}

func (s *Stream) WaitConnected(timeout time.Duration) bool {
	select {
	case <-s.Connected:
		return true
	case <-time.After(timeout):
		return false
	case <-s.CloseCh:
		return false
	}
}

// ==================== 流管理器 ====================

type Manager struct {
	streams sync.Map
	counter uint32
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) NewStreamID() uint32 {
	return atomic.AddUint32(&m.counter, 1)
}

func (m *Manager) Register(s *Stream) {
	m.streams.Store(s.ID, s)
	metrics.IncrActiveStreams()
}

func (m *Manager) Unregister(id uint32) {
	if v, ok := m.streams.LoadAndDelete(id); ok {
		s := v.(*Stream)
		if !s.IsClosed() {
			s.Close()
		}
	}
}

func (m *Manager) Get(id uint32) *Stream {
	if v, ok := m.streams.Load(id); ok {
		return v.(*Stream)
	}
	return nil
}

func (m *Manager) CloseAll() {
	m.streams.Range(func(key, value any) bool {
		s := value.(*Stream)
		s.Close()
		m.streams.Delete(key)
		return true
	})
}

func (m *Manager) Count() int {
	count := 0
	m.streams.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

func (m *Manager) Range(f func(id uint32, s *Stream) bool) {
	m.streams.Range(func(key, value any) bool {
		return f(key.(uint32), value.(*Stream))
	})
}

func (m *Manager) CleanupTimeout(timeout time.Duration) int {
	now := time.Now()
	count := 0
	m.streams.Range(func(key, value any) bool {
		s := value.(*Stream)
		if now.Sub(s.CreatedAt) > timeout && s.GetState() != StateConnected {
			s.Close()
			m.streams.Delete(key)
			count++
		}
		return true
	})
	return count
}
