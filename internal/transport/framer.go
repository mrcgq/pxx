
//internal/transport/framer.go

package transport

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"phantom-x/internal/proto"
)

// ==================== 错误定义 ====================

var (
	ErrPayloadTooLarge = errors.New("payload too large")
	ErrInvalidFrame    = errors.New("invalid frame")
	ErrBufferTooSmall  = errors.New("buffer too small")
)

// ==================== Frame 对象池 ====================

var framePool = sync.Pool{
	New: func() any {
		return &proto.Frame{
			Payload: make([]byte, 0, 4096),
		}
	},
}

// GetFrame 从对象池获取 Frame
func GetFrame() *proto.Frame {
	return framePool.Get().(*proto.Frame)
}

// PutFrame 将 Frame 归还到对象池
func PutFrame(f *proto.Frame) {
	if f == nil {
		return
	}
	// 重置字段但保留 Payload 的容量
	f.Cmd = 0
	f.StreamID = 0
	f.Flags = 0
	f.Payload = f.Payload[:0]
	framePool.Put(f)
}

// ==================== 缓冲区池 ====================

// BufferPool 统一的缓冲区池管理
type BufferPool struct {
	small  sync.Pool // 4KB
	medium sync.Pool // 32KB
	large  sync.Pool // 64KB
}

var bufferPool = &BufferPool{
	small: sync.Pool{
		New: func() any {
			b := make([]byte, 4*1024)
			return &b
		},
	},
	medium: sync.Pool{
		New: func() any {
			b := make([]byte, 32*1024)
			return &b
		},
	},
	large: sync.Pool{
		New: func() any {
			b := make([]byte, 64*1024)
			return &b
		},
	},
}

// 导出的缓冲区池（向后兼容）
var (
	SmallBufPool  = &bufferPool.small
	MediumBufPool = &bufferPool.medium
	LargeBufPool  = &bufferPool.large
)

// GetSmallBuf 获取 4KB 缓冲区
func GetSmallBuf() *[]byte {
	return bufferPool.small.Get().(*[]byte)
}

// PutSmallBuf 归还 4KB 缓冲区
func PutSmallBuf(b *[]byte) {
	if b == nil {
		return
	}
	bufferPool.small.Put(b)
}

// GetMediumBuf 获取 32KB 缓冲区
func GetMediumBuf() *[]byte {
	return bufferPool.medium.Get().(*[]byte)
}

// PutMediumBuf 归还 32KB 缓冲区
func PutMediumBuf(b *[]byte) {
	if b == nil {
		return
	}
	bufferPool.medium.Put(b)
}

// GetLargeBuf 获取 64KB 缓冲区
func GetLargeBuf() *[]byte {
	return bufferPool.large.Get().(*[]byte)
}

// PutLargeBuf 归还 64KB 缓冲区
func PutLargeBuf(b *[]byte) {
	if b == nil {
		return
	}
	bufferPool.large.Put(b)
}

// GetBuffer 根据大小获取合适的缓冲区
func GetBuffer(size int) *[]byte {
	switch {
	case size <= 4*1024:
		return GetSmallBuf()
	case size <= 32*1024:
		return GetMediumBuf()
	default:
		return GetLargeBuf()
	}
}

// PutBuffer 根据大小归还缓冲区
func PutBuffer(b *[]byte) {
	if b == nil {
		return
	}
	size := cap(*b)
	switch {
	case size <= 4*1024:
		PutSmallBuf(b)
	case size <= 32*1024:
		PutMediumBuf(b)
	default:
		PutLargeBuf(b)
	}
}

// ==================== 帧读取器 ====================

type FrameReader struct {
	r          io.Reader
	headerBuf  []byte
	payloadBuf []byte
	maxPayload int
	mu         sync.Mutex
}

func NewFrameReader(r io.Reader, maxPayload int) *FrameReader {
	if maxPayload <= 0 {
		maxPayload = proto.MaxPayload
	}
	return &FrameReader{
		r:          r,
		headerBuf:  make([]byte, proto.HeaderLen),
		payloadBuf: make([]byte, maxPayload),
		maxPayload: maxPayload,
	}
}

// ReadFrame 读取并返回一个帧（返回独立的数据拷贝，安全）
func (fr *FrameReader) ReadFrame() (*proto.Frame, error) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	// 读取头部
	if _, err := io.ReadFull(fr.r, fr.headerBuf); err != nil {
		return nil, err
	}

	cmd, streamID, flags, length := proto.UnpackHeader(fr.headerBuf)

	// 验证长度
	if length > fr.maxPayload {
		return nil, ErrPayloadTooLarge
	}

	// 读取 payload
	var payload []byte
	if length > 0 {
		if _, err := io.ReadFull(fr.r, fr.payloadBuf[:length]); err != nil {
			return nil, err
		}

		// 创建独立的拷贝，避免后续读取覆盖数据
		payload = make([]byte, length)
		copy(payload, fr.payloadBuf[:length])

		// 处理 Padding
		if flags&proto.FlagPadding != 0 {
			payload = proto.RemovePadding(payload)
		}
	}

	return &proto.Frame{
		Cmd:      cmd,
		StreamID: streamID,
		Flags:    flags,
		Payload:  payload,
	}, nil
}

// ReadFrameNoCopy 读取帧但不拷贝数据（调用者必须在下次调用前使用完数据）
// 性能更好但使用需谨慎
func (fr *FrameReader) ReadFrameNoCopy() (*proto.Frame, error) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	// 读取头部
	if _, err := io.ReadFull(fr.r, fr.headerBuf); err != nil {
		return nil, err
	}

	cmd, streamID, flags, length := proto.UnpackHeader(fr.headerBuf)

	// 验证长度
	if length > fr.maxPayload {
		return nil, ErrPayloadTooLarge
	}

	// 读取 payload（直接使用内部缓冲区）
	var payload []byte
	if length > 0 {
		if _, err := io.ReadFull(fr.r, fr.payloadBuf[:length]); err != nil {
			return nil, err
		}

		payload = fr.payloadBuf[:length]

		// 处理 Padding
		if flags&proto.FlagPadding != 0 {
			payload = proto.RemovePadding(payload)
		}
	}

	return &proto.Frame{
		Cmd:      cmd,
		StreamID: streamID,
		Flags:    flags,
		Payload:  payload,
	}, nil
}

// ReadFrameInto 读取帧到提供的 Frame 对象中（用于对象池场景）
func (fr *FrameReader) ReadFrameInto(frame *proto.Frame) error {
	if frame == nil {
		return errors.New("nil frame")
	}

	fr.mu.Lock()
	defer fr.mu.Unlock()

	// 读取头部
	if _, err := io.ReadFull(fr.r, fr.headerBuf); err != nil {
		return err
	}

	cmd, streamID, flags, length := proto.UnpackHeader(fr.headerBuf)

	// 验证长度
	if length > fr.maxPayload {
		return ErrPayloadTooLarge
	}

	frame.Cmd = cmd
	frame.StreamID = streamID
	frame.Flags = flags

	// 读取 payload
	if length > 0 {
		if _, err := io.ReadFull(fr.r, fr.payloadBuf[:length]); err != nil {
			return err
		}

		// 确保 Payload 容量足够
		if cap(frame.Payload) < length {
			frame.Payload = make([]byte, length)
		} else {
			frame.Payload = frame.Payload[:length]
		}
		copy(frame.Payload, fr.payloadBuf[:length])

		// 处理 Padding
		if flags&proto.FlagPadding != 0 {
			frame.Payload = proto.RemovePadding(frame.Payload)
		}
	} else {
		frame.Payload = frame.Payload[:0]
	}

	return nil
}

// ==================== 帧写入器 ====================

type FrameWriter struct {
	w       io.Writer
	buf     []byte
	bufSize int
	mu      sync.Mutex
}

func NewFrameWriter(w io.Writer, bufSize int) *FrameWriter {
	if bufSize <= 0 {
		bufSize = 64 * 1024
	}
	return &FrameWriter{
		w:       w,
		buf:     make([]byte, bufSize),
		bufSize: bufSize,
	}
}

// WriteFrame 写入帧
func (fw *FrameWriter) WriteFrame(frame *proto.Frame) error {
	if frame == nil {
		return errors.New("nil frame")
	}

	fw.mu.Lock()
	defer fw.mu.Unlock()

	totalLen := proto.HeaderLen + len(frame.Payload)
	if totalLen > fw.bufSize {
		return ErrBufferTooSmall
	}

	n := proto.PackFrame(fw.buf, frame.Cmd, frame.StreamID, frame.Flags, frame.Payload, 0)
	_, err := fw.w.Write(fw.buf[:n])
	return err
}

// WriteFrameWithPadding 写入带填充的帧
func (fw *FrameWriter) WriteFrameWithPadding(frame *proto.Frame, paddingCalc *proto.PaddingCalculator) error {
	if frame == nil {
		return errors.New("nil frame")
	}

	fw.mu.Lock()
	defer fw.mu.Unlock()

	n := proto.PackFrameWithPadding(fw.buf, frame.Cmd, frame.StreamID, frame.Flags, frame.Payload, paddingCalc)
	if n > fw.bufSize {
		return ErrBufferTooSmall
	}
	
	_, err := fw.w.Write(fw.buf[:n])
	return err
}

// WriteRaw 直接写入原始数据
func (fw *FrameWriter) WriteRaw(data []byte) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	
	_, err := fw.w.Write(data)
	return err
}

// WriteFrameDirect 直接写入帧，不使用内部缓冲区（用于大帧）
func (fw *FrameWriter) WriteFrameDirect(cmd byte, streamID uint32, flags byte, payload []byte) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	// 写入头部
	header := make([]byte, proto.HeaderLen)
	proto.PackHeader(header, cmd, streamID, flags, len(payload))
	
	if _, err := fw.w.Write(header); err != nil {
		return err
	}

	// 写入 payload
	if len(payload) > 0 {
		if _, err := fw.w.Write(payload); err != nil {
			return err
		}
	}

	return nil
}

// ==================== 批量帧写入器 ====================

type BatchFrameWriter struct {
	w         io.Writer
	buf       []byte
	offset    int
	maxBatch  int
	mu        sync.Mutex
}

func NewBatchFrameWriter(w io.Writer, bufSize int) *BatchFrameWriter {
	if bufSize <= 0 {
		bufSize = 256 * 1024
	}
	return &BatchFrameWriter{
		w:        w,
		buf:      make([]byte, bufSize),
		maxBatch: bufSize,
	}
}

// AddFrame 添加帧到批量缓冲区
func (bw *BatchFrameWriter) AddFrame(frame *proto.Frame) error {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	frameLen := proto.HeaderLen + len(frame.Payload)
	
	// 如果添加这个帧会超出缓冲区，先刷新
	if bw.offset+frameLen > bw.maxBatch {
		if err := bw.flushLocked(); err != nil {
			return err
		}
	}

	// 如果单个帧就超过缓冲区大小
	if frameLen > bw.maxBatch {
		return ErrBufferTooSmall
	}

	n := proto.PackFrame(bw.buf[bw.offset:], frame.Cmd, frame.StreamID, frame.Flags, frame.Payload, 0)
	bw.offset += n
	return nil
}

// Flush 刷新缓冲区
func (bw *BatchFrameWriter) Flush() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return bw.flushLocked()
}

func (bw *BatchFrameWriter) flushLocked() error {
	if bw.offset == 0 {
		return nil
	}

	_, err := bw.w.Write(bw.buf[:bw.offset])
	bw.offset = 0
	return err
}

// Pending 返回待发送的字节数
func (bw *BatchFrameWriter) Pending() int {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return bw.offset
}

// ==================== 编解码辅助 ====================

func EncodeUint16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func DecodeUint16(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func EncodeUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func DecodeUint32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func EncodeUint64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func DecodeUint64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// ==================== 帧构建辅助 ====================

// BuildDataFrame 构建数据帧
func BuildDataFrame(streamID uint32, data []byte) *proto.Frame {
	return &proto.Frame{
		Cmd:      proto.CmdData,
		StreamID: streamID,
		Flags:    0,
		Payload:  data,
	}
}

// BuildCloseFrame 构建关闭帧
func BuildCloseFrame(streamID uint32) *proto.Frame {
	return &proto.Frame{
		Cmd:      proto.CmdClose,
		StreamID: streamID,
		Flags:    0,
		Payload:  nil,
	}
}

// BuildOpenTCPFrame 构建 TCP 打开帧
func BuildOpenTCPFrame(streamID uint32, ipStrategy byte, host string, port uint16, initData []byte) *proto.Frame {
	return &proto.Frame{
		Cmd:      proto.CmdOpenTCP,
		StreamID: streamID,
		Flags:    0,
		Payload:  proto.BuildOpenPayload(ipStrategy, host, port, initData),
	}
}

// BuildOpenUDPFrame 构建 UDP 打开帧
func BuildOpenUDPFrame(streamID uint32, ipStrategy byte, host string, port uint16) *proto.Frame {
	return &proto.Frame{
		Cmd:      proto.CmdOpenUDP,
		StreamID: streamID,
		Flags:    0,
		Payload:  proto.BuildOpenPayload(ipStrategy, host, port, nil),
	}
}

// BuildConnStatusFrame 构建连接状态帧
func BuildConnStatusFrame(streamID uint32, status byte) *proto.Frame {
	return &proto.Frame{
		Cmd:      proto.CmdConnStatus,
		StreamID: streamID,
		Flags:    0,
		Payload:  []byte{status},
	}
}

