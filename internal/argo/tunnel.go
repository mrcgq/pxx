package argo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	plog "phantom-x/pkg/log"
)

// ==================== 常量定义 ====================

const (
	TunnelStartTimeout  = 30 * time.Second
	TunnelCheckInterval = 5 * time.Second
	DomainRegex         = `https://([a-z0-9-]+\.trycloudflare\.com)`
)

var (
	ErrTunnelStartFailed   = errors.New("tunnel start failed")
	ErrTunnelNotRunning    = errors.New("tunnel not running")
	ErrCloudflaredNotFound = errors.New("cloudflared not found")
	domainPattern          = regexp.MustCompile(DomainRegex)
)

// ==================== 隧道状态 ====================

type TunnelStatus int32

const (
	TunnelStatusStopped TunnelStatus = iota
	TunnelStatusStarting
	TunnelStatusRunning
	TunnelStatusFailed
)

func (s TunnelStatus) String() string {
	switch s {
	case TunnelStatusStopped:
		return "stopped"
	case TunnelStatusStarting:
		return "starting"
	case TunnelStatusRunning:
		return "running"
	case TunnelStatusFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// ==================== Argo 隧道管理器 ====================

type Tunnel struct {
	cloudflaredPath string
	localPort       int
	protocol        string // "http" 或 "https"
	noTLSVerify     bool

	domain       string
	status       int32
	cmd          *exec.Cmd
	logFile      string
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	startTime    time.Time
	restartCount int32

	// 回调
	OnDomainReady  func(domain string)
	OnTunnelClosed func(err error)
}

type TunnelConfig struct {
	CloudflaredPath string
	LocalPort       int
	Protocol        string // "http" 或 "https"
	NoTLSVerify     bool
}

func NewTunnel(cfg *TunnelConfig) *Tunnel {
	if cfg.Protocol == "" {
		cfg.Protocol = "https"
	}
	if cfg.LocalPort == 0 {
		cfg.LocalPort = findFreePort()
	}

	return &Tunnel{
		cloudflaredPath: cfg.CloudflaredPath,
		localPort:       cfg.LocalPort,
		protocol:        cfg.Protocol,
		noTLSVerify:     cfg.NoTLSVerify,
		logFile:         fmt.Sprintf("%s/cloudflared_%d.log", os.TempDir(), cfg.LocalPort),
	}
}

// Start 启动隧道并返回分配的域名
func (t *Tunnel) Start(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.GetStatus() == TunnelStatusRunning {
		return t.domain, nil
	}

	atomic.StoreInt32(&t.status, int32(TunnelStatusStarting))
	t.startTime = time.Now()

	// 检查 cloudflared
	if t.cloudflaredPath == "" {
		return "", ErrCloudflaredNotFound
	}

	// 清理旧日志
	_ = os.Remove(t.logFile)

	// 创建上下文
	t.ctx, t.cancel = context.WithCancel(ctx)

	// 构建命令参数
	localURL := fmt.Sprintf("%s://localhost:%d", t.protocol, t.localPort)
	args := []string{"tunnel", "--url", localURL, "--logfile", t.logFile}

	if t.noTLSVerify {
		args = append(args, "--no-tls-verify")
	}

	plog.Info("[Argo] 启动隧道: %s -> %s", localURL, t.cloudflaredPath)

	// 启动进程
	t.cmd = exec.CommandContext(t.ctx, t.cloudflaredPath, args...)
	t.cmd.Stdout = nil
	t.cmd.Stderr = nil

	if err := t.cmd.Start(); err != nil {
		atomic.StoreInt32(&t.status, int32(TunnelStatusFailed))
		return "", fmt.Errorf("start cloudflared: %w", err)
	}

	// 等待域名分配
	domain, err := t.waitForDomain(ctx)
	if err != nil {
		t.Stop()
		return "", err
	}

	t.domain = domain
	atomic.StoreInt32(&t.status, int32(TunnelStatusRunning))

	// 启动监控
	go t.monitor()

	plog.Info("[Argo] 隧道已建立: %s", domain)

	if t.OnDomainReady != nil {
		go t.OnDomainReady(domain)
	}

	return domain, nil
}

// waitForDomain 等待从日志中提取域名
func (t *Tunnel) waitForDomain(ctx context.Context) (string, error) {
	timeout := time.After(TunnelStartTimeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timeout:
			return "", fmt.Errorf("timeout waiting for tunnel domain")
		case <-ticker.C:
			domain := t.extractDomainFromLog()
			if domain != "" {
				return domain, nil
			}
		}
	}
}

// extractDomainFromLog 从日志文件提取域名
func (t *Tunnel) extractDomainFromLog() string {
	file, err := os.Open(t.logFile)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := domainPattern.FindStringSubmatch(line)
		if len(matches) >= 2 {
			return matches[1] // 返回完整域名 xxx.trycloudflare.com
		}
	}
	return ""
}

// Stop 停止隧道
func (t *Tunnel) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.cancel != nil {
		t.cancel()
	}

	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
		_ = t.cmd.Wait()
	}

	atomic.StoreInt32(&t.status, int32(TunnelStatusStopped))
	t.domain = ""

	plog.Info("[Argo] 隧道已停止")
}

// Restart 重启隧道
func (t *Tunnel) Restart(ctx context.Context) (string, error) {
	t.Stop()
	time.Sleep(time.Second)
	atomic.AddInt32(&t.restartCount, 1)
	return t.Start(ctx)
}

// monitor 监控隧道进程
func (t *Tunnel) monitor() {
	if t.cmd == nil {
		return
	}

	err := t.cmd.Wait()

	if t.GetStatus() == TunnelStatusRunning {
		atomic.StoreInt32(&t.status, int32(TunnelStatusFailed))
		plog.Warn("[Argo] 隧道进程异常退出: %v", err)

		if t.OnTunnelClosed != nil {
			t.OnTunnelClosed(err)
		}
	}
}

// GetDomain 获取当前隧道域名
func (t *Tunnel) GetDomain() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.domain
}

// GetStatus 获取隧道状态
func (t *Tunnel) GetStatus() TunnelStatus {
	return TunnelStatus(atomic.LoadInt32(&t.status))
}

// IsRunning 检查隧道是否运行中
func (t *Tunnel) IsRunning() bool {
	return t.GetStatus() == TunnelStatusRunning
}

// GetLocalPort 获取本地端口
func (t *Tunnel) GetLocalPort() int {
	return t.localPort
}

// GetUptime 获取运行时长
func (t *Tunnel) GetUptime() time.Duration {
	if t.GetStatus() != TunnelStatusRunning {
		return 0
	}
	return time.Since(t.startTime)
}

// GetRestartCount 获取重启次数
func (t *Tunnel) GetRestartCount() int32 {
	return atomic.LoadInt32(&t.restartCount)
}

// GetFullURL 获取完整的隧道 URL
func (t *Tunnel) GetFullURL() string {
	domain := t.GetDomain()
	if domain == "" {
		return ""
	}
	return "https://" + domain
}

// ==================== 辅助函数 ====================

// findFreePort 寻找可用端口
func findFreePort() int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 18080 // 默认端口
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}
