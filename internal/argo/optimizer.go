package argo

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	plog "phantom-x/pkg/log"
)

// ==================== Cloudflare IP 段 ====================

var cfIPRanges = []string{
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
}

// ==================== IP 测试结果 ====================

type IPTestResult struct {
	IP      string
	Latency time.Duration
	Success bool
}

// ==================== CF 优选器 ====================

type CFOptimizer struct {
	candidateIPs   []string
	optimalIP      string
	optimalLatency time.Duration
	testDomain     string
	testPort       string
	concurrency    int
	timeout        time.Duration

	mu           sync.RWMutex
	lastOptimize time.Time
	testing      int32
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

type CFOptimizerConfig struct {
	TestCount   int
	Concurrency int
	Timeout     time.Duration
	TestDomain  string
	TestPort    string
}

func NewCFOptimizer(cfg *CFOptimizerConfig) *CFOptimizer {
	if cfg.TestCount <= 0 {
		cfg.TestCount = 200
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 50
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.TestDomain == "" {
		cfg.TestDomain = "speed.cloudflare.com"
	}
	if cfg.TestPort == "" {
		cfg.TestPort = "443"
	}

	o := &CFOptimizer{
		candidateIPs: generateCandidateIPs(cfg.TestCount),
		testDomain:   cfg.TestDomain,
		testPort:     cfg.TestPort,
		concurrency:  cfg.Concurrency,
		timeout:      cfg.Timeout,
		stopCh:       make(chan struct{}),
	}

	return o
}

// generateCandidateIPs 从 Cloudflare IP 段生成候选 IP
func generateCandidateIPs(count int) []string {
	var allIPs []string

	for _, cidr := range cfIPRanges {
		ips := expandCIDR(cidr, count/len(cfIPRanges)+10)
		allIPs = append(allIPs, ips...)
	}

	// 打乱顺序
	rand.Shuffle(len(allIPs), func(i, j int) {
		allIPs[i], allIPs[j] = allIPs[j], allIPs[i]
	})

	if len(allIPs) > count {
		allIPs = allIPs[:count]
	}

	return allIPs
}

// expandCIDR 从 CIDR 扩展出 IP 列表
func expandCIDR(cidr string, maxCount int) []string {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	var ips []string
	ip := network.IP.To4()
	if ip == nil {
		return nil
	}

	// 从网段中随机选取 IP
	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	maxHosts := 1 << hostBits

	if maxHosts > maxCount*10 {
		// 大网段，随机选取
		for i := 0; i < maxCount && len(ips) < maxCount; i++ {
			offset := rand.Intn(maxHosts)
			newIP := make(net.IP, 4)
			copy(newIP, ip)
			newIP[3] = byte((int(ip[3]) + offset) % 256)
			newIP[2] = byte((int(ip[2]) + offset/256) % 256)
			ips = append(ips, newIP.String())
		}
	} else {
		// 小网段，遍历
		for i := 0; i < maxHosts && len(ips) < maxCount; i++ {
			newIP := make(net.IP, 4)
			copy(newIP, ip)
			newIP[3] = byte((int(ip[3]) + i) % 256)
			newIP[2] = byte((int(ip[2]) + i/256) % 256)
			ips = append(ips, newIP.String())
		}
	}

	return ips
}

// FindOptimalIP 执行 IP 优选
func (o *CFOptimizer) FindOptimalIP(ctx context.Context) (string, time.Duration, error) {
	if !atomic.CompareAndSwapInt32(&o.testing, 0, 1) {
		// 正在测试中，返回缓存结果
		o.mu.RLock()
		ip, latency := o.optimalIP, o.optimalLatency
		o.mu.RUnlock()
		if ip != "" {
			return ip, latency, nil
		}
		return "", 0, nil
	}
	defer atomic.StoreInt32(&o.testing, 0)

	plog.Info("[CFOptimize] 开始优选 Cloudflare IP (%d 个候选)", len(o.candidateIPs))

	results := make(chan IPTestResult, len(o.candidateIPs))
	semaphore := make(chan struct{}, o.concurrency)

	var wg sync.WaitGroup
	startTime := time.Now()

	for _, ip := range o.candidateIPs {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			latency, ok := o.testIP(ctx, ip)
			results <- IPTestResult{IP: ip, Latency: latency, Success: ok}
		}(ip)
	}

	// 等待完成
	go func() {
		wg.Wait()
		close(results)
	}()

	// 收集结果
	var successResults []IPTestResult
	for result := range results {
		if result.Success {
			successResults = append(successResults, result)
		}
	}

	if len(successResults) == 0 {
		plog.Warn("[CFOptimize] 没有可用的 IP")
		return "", 0, nil
	}

	// 按延迟排序
	sort.Slice(successResults, func(i, j int) bool {
		return successResults[i].Latency < successResults[j].Latency
	})

	best := successResults[0]

	o.mu.Lock()
	o.optimalIP = best.IP
	o.optimalLatency = best.Latency
	o.lastOptimize = time.Now()
	o.mu.Unlock()

	elapsed := time.Since(startTime)
	plog.Info("[CFOptimize] 优选完成: %s (延迟: %v, 成功: %d/%d, 耗时: %v)",
		best.IP, best.Latency, len(successResults), len(o.candidateIPs), elapsed)

	// 打印 Top 5
	if plog.IsDebugEnabled() {
		top := 5
		if len(successResults) < top {
			top = len(successResults)
		}
		for i := 0; i < top; i++ {
			plog.Debug("[CFOptimize] Top %d: %s (%v)", i+1, successResults[i].IP, successResults[i].Latency)
		}
	}

	return best.IP, best.Latency, nil
}

// testIP 测试单个 IP 的延迟
func (o *CFOptimizer) testIP(ctx context.Context, ip string) (time.Duration, bool) {
	start := time.Now()
	addr := net.JoinHostPort(ip, o.testPort)

	// 建立 TCP 连接
	dialer := &net.Dialer{Timeout: o.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, false
	}
	defer func() { _ = conn.Close() }()

	// TLS 握手
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         o.testDomain,
		InsecureSkipVerify: true, // 只测延迟，不验证证书
	})

	if err := tlsConn.SetDeadline(time.Now().Add(o.timeout)); err != nil {
		return 0, false
	}

	if err := tlsConn.Handshake(); err != nil {
		return 0, false
	}

	return time.Since(start), true
}

// GetOptimalIP 获取缓存的最优 IP
func (o *CFOptimizer) GetOptimalIP() (string, time.Duration) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.optimalIP, o.optimalLatency
}

// SetOptimalIP 手动设置优选 IP
func (o *CFOptimizer) SetOptimalIP(ip string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.optimalIP = ip
	o.optimalLatency = 0 // 手动设置时延迟未知
	o.lastOptimize = time.Now()
	plog.Info("[CFOptimize] 手动设置优选 IP: %s", ip)
}

// StartAutoRefresh 启动定期优选
func (o *CFOptimizer) StartAutoRefresh(ctx context.Context, interval time.Duration) {
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-o.stopCh:
				return
			case <-ticker.C:
				_, _, _ = o.FindOptimalIP(ctx)
			}
		}
	}()
}

// Stop 停止优选器
func (o *CFOptimizer) Stop() {
	close(o.stopCh)
	o.wg.Wait()
}

// GetLastOptimizeTime 获取上次优选时间
func (o *CFOptimizer) GetLastOptimizeTime() time.Time {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.lastOptimize
}
