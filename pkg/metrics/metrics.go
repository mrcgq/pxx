

//pkg/metrics/metrics.go
package metrics

import (
	"fmt"
	"sync/atomic"
	"time"
)

// 全局指标
var (
	packetsSent       int64
	packetsRecv       int64
	bytesSent         int64
	bytesRecv         int64
	activeStreams     int64
	activeConnections int64
	totalConnections  int64
	writeTimeouts     int64
	connectErrors     int64
	reconnectCount    int64
	startTime         = time.Now()
)

func IncrPacketsSent(n int64)   { atomic.AddInt64(&packetsSent, n) }
func IncrPacketsRecv(n int64)   { atomic.AddInt64(&packetsRecv, n) }
func AddBytesSent(n int64)      { atomic.AddInt64(&bytesSent, n) }
func AddBytesRecv(n int64)      { atomic.AddInt64(&bytesRecv, n) }
func IncrActiveStreams()        { atomic.AddInt64(&activeStreams, 1) }
func DecrActiveStreams()        { atomic.AddInt64(&activeStreams, -1) }
func IncrActiveConnections()    { atomic.AddInt64(&activeConnections, 1) }
func DecrActiveConnections()    { atomic.AddInt64(&activeConnections, -1) }
func IncrTotalConnections()     { atomic.AddInt64(&totalConnections, 1) }
func IncrWriteTimeout()         { atomic.AddInt64(&writeTimeouts, 1) }
func IncrConnectError()         { atomic.AddInt64(&connectErrors, 1) }
func IncrReconnectCount()       { atomic.AddInt64(&reconnectCount, 1) }

// Stats 获取统计信息
type Stats struct {
	Uptime            time.Duration
	PacketsSent       int64
	PacketsRecv       int64
	BytesSent         int64
	BytesRecv         int64
	ActiveStreams     int64
	ActiveConnections int64
	TotalConnections  int64
	WriteTimeouts     int64
	ConnectErrors     int64
	ReconnectCount    int64
}

func GetStats() Stats {
	return Stats{
		Uptime:            time.Since(startTime),
		PacketsSent:       atomic.LoadInt64(&packetsSent),
		PacketsRecv:       atomic.LoadInt64(&packetsRecv),
		BytesSent:         atomic.LoadInt64(&bytesSent),
		BytesRecv:         atomic.LoadInt64(&bytesRecv),
		ActiveStreams:     atomic.LoadInt64(&activeStreams),
		ActiveConnections: atomic.LoadInt64(&activeConnections),
		TotalConnections:  atomic.LoadInt64(&totalConnections),
		WriteTimeouts:     atomic.LoadInt64(&writeTimeouts),
		ConnectErrors:     atomic.LoadInt64(&connectErrors),
		ReconnectCount:    atomic.LoadInt64(&reconnectCount),
	}
}

func (s Stats) String() string {
	return fmt.Sprintf(
		"Uptime: %v | Conns: %d/%d | Streams: %d | TX: %d pkts/%s | RX: %d pkts/%s | Errors: %d",
		s.Uptime.Round(time.Second),
		s.ActiveConnections, s.TotalConnections,
		s.ActiveStreams,
		s.PacketsSent, formatBytes(s.BytesSent),
		s.PacketsRecv, formatBytes(s.BytesRecv),
		s.WriteTimeouts+s.ConnectErrors,
	)
}

// ExportPrometheus 导出 Prometheus 格式的指标
func ExportPrometheus() string {
	stats := GetStats()
	return fmt.Sprintf(`# HELP phantom_x_uptime_seconds Server uptime in seconds
# TYPE phantom_x_uptime_seconds gauge
phantom_x_uptime_seconds %.0f

# HELP phantom_x_bytes_sent_total Total bytes sent
# TYPE phantom_x_bytes_sent_total counter
phantom_x_bytes_sent_total %d

# HELP phantom_x_bytes_recv_total Total bytes received
# TYPE phantom_x_bytes_recv_total counter
phantom_x_bytes_recv_total %d

# HELP phantom_x_packets_sent_total Total packets sent
# TYPE phantom_x_packets_sent_total counter
phantom_x_packets_sent_total %d

# HELP phantom_x_packets_recv_total Total packets received
# TYPE phantom_x_packets_recv_total counter
phantom_x_packets_recv_total %d

# HELP phantom_x_active_streams Current number of active streams
# TYPE phantom_x_active_streams gauge
phantom_x_active_streams %d

# HELP phantom_x_active_connections Current number of active connections
# TYPE phantom_x_active_connections gauge
phantom_x_active_connections %d

# HELP phantom_x_total_connections_total Total number of connections
# TYPE phantom_x_total_connections_total counter
phantom_x_total_connections_total %d

# HELP phantom_x_write_timeouts_total Total write timeouts
# TYPE phantom_x_write_timeouts_total counter
phantom_x_write_timeouts_total %d

# HELP phantom_x_connect_errors_total Total connection errors
# TYPE phantom_x_connect_errors_total counter
phantom_x_connect_errors_total %d

# HELP phantom_x_reconnect_count_total Total reconnection attempts
# TYPE phantom_x_reconnect_count_total counter
phantom_x_reconnect_count_total %d
`,
		stats.Uptime.Seconds(),
		stats.BytesSent,
		stats.BytesRecv,
		stats.PacketsSent,
		stats.PacketsRecv,
		stats.ActiveStreams,
		stats.ActiveConnections,
		stats.TotalConnections,
		stats.WriteTimeouts,
		stats.ConnectErrors,
		stats.ReconnectCount,
	)
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// Reset 重置所有指标（用于测试）
func Reset() {
	atomic.StoreInt64(&packetsSent, 0)
	atomic.StoreInt64(&packetsRecv, 0)
	atomic.StoreInt64(&bytesSent, 0)
	atomic.StoreInt64(&bytesRecv, 0)
	atomic.StoreInt64(&activeStreams, 0)
	atomic.StoreInt64(&activeConnections, 0)
	atomic.StoreInt64(&totalConnections, 0)
	atomic.StoreInt64(&writeTimeouts, 0)
	atomic.StoreInt64(&connectErrors, 0)
	atomic.StoreInt64(&reconnectCount, 0)
}


