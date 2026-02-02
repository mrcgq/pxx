
//cmd/client/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"phantom-x/internal/argo"
	"phantom-x/internal/pool"
	"phantom-x/internal/proto"
	"phantom-x/internal/socks5"
	"phantom-x/internal/stream"
	"phantom-x/pkg/config"
	plog "phantom-x/pkg/log"
	"phantom-x/pkg/metrics"
)

var (
	Version   = "1.1.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	configPath := flag.String("c", "", "配置文件路径")
	showVersion := flag.Bool("v", false, "显示版本")
	showStats := flag.Bool("stats", false, "退出时显示统计")

	serverAddr := flag.String("s", "", "服务器地址")
	token := flag.String("token", "", "认证令牌")
	socksAddr := flag.String("l", "", "SOCKS5监听地址")
	insecure := flag.Bool("insecure", false, "跳过证书验证")
	noUTLS := flag.Bool("no-utls", false, "禁用 uTLS 指纹")
	fingerprint := flag.String("fp", "", "TLS 指纹 (chrome/firefox/safari/ios/android)")
	
	// Argo 相关
	enableArgo := flag.Bool("argo", false, "启用 Argo 隧道")
	argoMode := flag.String("argo-mode", "", "Argo 模式 (auto/always/fallback)")
	cfOptimize := flag.Bool("cf-optimize", false, "启用 Cloudflare IP 优选")
	cfIP := flag.String("cf-ip", "", "手动指定 Cloudflare IP")

	flag.Parse()

	if *showVersion {
		fmt.Printf("Phantom-X Client v%s\n", Version)
		fmt.Printf("  Build: %s\n", BuildTime)
		fmt.Printf("  Commit: %s\n", GitCommit)
		fmt.Printf("  Features: uTLS, Argo Tunnel, CF Optimize\n")
		return
	}

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		plog.Warn("Load config failed, using defaults: %v", err)
		cfg = config.DefaultClientConfig()
	}

	// 命令行参数覆盖配置
	if *serverAddr != "" {
		cfg.Server = *serverAddr
	}
	if *token != "" {
		cfg.Token = *token
	}
	if *socksAddr != "" {
		cfg.Socks5Listen = *socksAddr
	}
	if *insecure {
		cfg.Insecure = true
	}
	if *noUTLS {
		cfg.EnableUTLS = false
	}
	if *fingerprint != "" {
		cfg.Fingerprint = *fingerprint
	}
	if *enableArgo {
		cfg.EnableArgo = true
	}
	if *argoMode != "" {
		cfg.ArgoMode = *argoMode
	}
	if *cfOptimize {
		cfg.EnableCFOptimize = true
	}
	if *cfIP != "" {
		cfg.PreferredCFIP = *cfIP
	}

	if err := cfg.Validate(); err != nil {
		plog.Fatalf("Config validation failed: %v", err)
	}

	plog.SetLevel(cfg.LogLevel)

	if cfg.ClientID == "" {
		cfg.ClientID = uuid.NewString()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ==================== 初始化 Argo 隧道 ====================
	var argoTunnel *argo.Tunnel
	var cfOptimizer *argo.CFOptimizer
	var effectiveServerURL string = cfg.Server
	var usingArgo bool

	if cfg.EnableArgo || cfg.ArgoMode == "always" || cfg.ArgoMode == "fallback" {
		plog.Info("[Argo] 初始化 Argo 隧道支持...")

		// 确保 cloudflared 可用
		cfdPath, err := argo.EnsureCloudflared(ctx, cfg.CloudflaredPath, cfg.AutoInstallCFD)
		if err != nil {
			if cfg.ArgoMode == "always" {
				plog.Fatalf("[Argo] cloudflared 不可用: %v", err)
			} else {
				plog.Warn("[Argo] cloudflared 不可用: %v，将使用直连模式", err)
			}
		} else {
			// 创建隧道
			argoTunnel = argo.NewTunnel(&argo.TunnelConfig{
				CloudflaredPath: cfdPath,
				LocalPort:       cfg.ArgoLocalPort,
				Protocol:        "https",
				NoTLSVerify:     true,
			})

			// always 模式立即启动
			if cfg.ArgoMode == "always" {
				domain, err := argoTunnel.Start(ctx)
				if err != nil {
					plog.Fatalf("[Argo] 隧道启动失败: %v", err)
				}
				effectiveServerURL = fmt.Sprintf("wss://%s%s", domain, getWSPath(cfg.Server))
				usingArgo = true
				plog.Info("[Argo] 使用隧道域名: %s", domain)
			}
		}
	}

	// ==================== 初始化 CF 优选 ====================
	if cfg.EnableCFOptimize && argoTunnel != nil {
		cfOptimizer = argo.NewCFOptimizer(&argo.CFOptimizerConfig{
			TestCount:   cfg.CFOptimizeCount,
			Concurrency: cfg.CFOptimizeConcurrency,
			Timeout:     3 * time.Second,
		})

		// 如果手动指定了 IP
		if cfg.PreferredCFIP != "" {
			cfOptimizer.SetOptimalIP(cfg.PreferredCFIP)
		} else if usingArgo {
			// Argo 模式下执行优选
			plog.Info("[CFOptimize] 执行 Cloudflare IP 优选...")
			if ip, latency, err := cfOptimizer.FindOptimalIP(ctx); err == nil && ip != "" {
				plog.Info("[CFOptimize] 最优 IP: %s (延迟: %v)", ip, latency)
			}

			// 启动定期优选
			cfOptimizer.StartAutoRefresh(ctx, cfg.CFOptimizeInterval)
		}
	}

	// ==================== 创建流管理器 ====================
	streamMgr := stream.NewManager()

	// ==================== 创建连接池配置 ====================
	poolCfg := &pool.Config{
		ServerURL:         effectiveServerURL,
		Token:             cfg.Token,
		ClientID:          cfg.ClientID,
		Insecure:          cfg.Insecure,
		NumConnections:    cfg.NumConnections,
		WriteQueueSize:    4096,
		WriteTimeout:      cfg.WriteTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		PingInterval:      30 * time.Second,
		ReconnectDelay:    time.Second,
		MaxBackoff:        30 * time.Second,
		EnableUTLS:        cfg.EnableUTLS,
		Fingerprint:       cfg.Fingerprint,
		EnablePadding:     cfg.EnablePadding,
		PaddingMinSize:    cfg.PaddingMinSize,
		PaddingMaxSize:    cfg.PaddingMaxSize,
		PaddingDistribute: cfg.PaddingDistribution,
		
		// Argo 相关
		ArgoTunnel:        argoTunnel,
		CFOptimizer:       cfOptimizer,
		ArgoFallback:      cfg.ArgoMode == "fallback" || cfg.ArgoMode == "auto",
		OriginalServerURL: cfg.Server,
	}

	connPool := pool.NewConnPool(poolCfg)

	// 创建 SOCKS5 服务器
	socks5Server := socks5.NewServer(cfg, streamMgr)

	// 设置帧处理器
	connPool.SetFrameHandler(func(connID int, streamID uint32, cmd byte, payload []byte) {
		handleServerFrame(streamMgr, socks5Server, connID, streamID, cmd, payload)
	})

	if err := connPool.Start(); err != nil {
		plog.Fatalf("Start connection pool failed: %v", err)
	}

	time.Sleep(time.Second)

	socks5Server.SetSendToFunc(func(connID int, cmd byte, streamID uint32, payload []byte) error {
		return connPool.SendTo(connID, proto.PackFrameAlloc(cmd, streamID, payload))
	})

	socks5Server.SetBroadcastFunc(func(cmd byte, streamID uint32, payload []byte) error {
		return connPool.Broadcast(proto.PackFrameAlloc(cmd, streamID, payload))
	})

	socks5Server.SetGetUplinkFunc(func(id uint32) (int, bool) {
		st := streamMgr.Get(id)
		if st != nil {
			connID := st.GetConnID()
			if connID >= 0 {
				return connID, true
			}
		}
		return 0, false
	})

	if err := socks5Server.Start(); err != nil {
		plog.Fatalf("Start SOCKS5 failed: %v", err)
	}

	printBanner(cfg, usingArgo, argoTunnel, cfOptimizer)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	plog.Info("Shutting down...")
	
	// 清理
	socks5Server.Stop()
	connPool.Stop()
	streamMgr.CloseAll()
	
	if argoTunnel != nil {
		argoTunnel.Stop()
	}
	if cfOptimizer != nil {
		cfOptimizer.Stop()
	}

	cancel()

	if *showStats {
		printStats()
	}
}

func handleServerFrame(mgr *stream.Manager, socks5Srv *socks5.Server, connID int, streamID uint32, cmd byte, payload []byte) {
	switch cmd {
	case proto.CmdConnStatus:
		st := mgr.Get(streamID)
		if st == nil {
			return
		}
		if len(payload) > 0 && payload[0] == proto.StatusOK {
			st.SetConnID(connID)
			st.SetState(stream.StateConnected)
			st.SignalConnected()
			plog.Debug("[Client] Stream %d connected via conn %d", streamID, connID)
		} else {
			plog.Debug("[Client] Stream %d connection failed", streamID)
			mgr.Unregister(streamID)
		}

	case proto.CmdData:
		st := mgr.Get(streamID)
		if st == nil {
			return
		}
		
		if st.IsUDP {
			if err := socks5Srv.HandleUDPResponse(streamID, payload); err != nil {
				plog.Debug("[Client] Failed to handle UDP response for stream %d: %v", streamID, err)
			}
		} else {
			if err := st.SendData(payload); err != nil {
				plog.Debug("[Client] Failed to send data to stream %d: %v", streamID, err)
			}
		}

	case proto.CmdClose:
		plog.Debug("[Client] Stream %d closed by server", streamID)
		st := mgr.Get(streamID)
		if st != nil && st.IsUDP {
			socks5Srv.HandleUDPClose(streamID)
		}
		mgr.Unregister(streamID)

	case proto.CmdPing:
		plog.Debug("[Client] Received ping from server")

	case proto.CmdPong:
		plog.Debug("[Client] Received pong from server")

	default:
		plog.Debug("[Client] Unknown command %d for stream %d", cmd, streamID)
	}
}

func getWSPath(serverURL string) string {
	// 从 URL 中提取 path
	if idx := len("wss://"); idx < len(serverURL) {
		rest := serverURL[idx:]
		if slashIdx := indexOf(rest, '/'); slashIdx >= 0 {
			return rest[slashIdx:]
		}
	}
	return "/ws"
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func printBanner(cfg *config.ClientConfig, usingArgo bool, tunnel *argo.Tunnel, optimizer *argo.CFOptimizer) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Phantom-X Client v1.1                           ║")
	fmt.Println("║              高性能 · 抗探测 · uTLS · Argo                    ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  服务器: %-47s ║\n", truncateString(cfg.Server, 47))
	fmt.Printf("║  SOCKS5: %-47s ║\n", cfg.Socks5Listen)
	fmt.Printf("║  连接数: %-47d ║\n", cfg.NumConnections)
	
	// uTLS 状态
	utlsStatus := "已禁用"
	if cfg.EnableUTLS {
		utlsStatus = fmt.Sprintf("已启用 (%s)", cfg.Fingerprint)
	}
	fmt.Printf("║  uTLS:   %-47s ║\n", utlsStatus)
	
	// Argo 状态
	argoStatus := "已禁用"
	if usingArgo && tunnel != nil {
		domain := tunnel.GetDomain()
		if domain != "" {
			argoStatus = fmt.Sprintf("已启用 (%s)", truncateString(domain, 30))
		} else {
			argoStatus = "已启用 (等待域名...)"
		}
	} else if cfg.ArgoMode == "fallback" {
		argoStatus = "回落模式 (待命)"
	}
	fmt.Printf("║  Argo:   %-47s ║\n", argoStatus)
	
	// CF 优选状态
	if optimizer != nil {
		ip, latency := optimizer.GetOptimalIP()
		if ip != "" {
			cfStatus := fmt.Sprintf("%s (%v)", ip, latency.Round(time.Millisecond))
			fmt.Printf("║  优选IP: %-47s ║\n", cfStatus)
		}
	}
	
	// Padding 状态
	paddingStatus := "已禁用"
	if cfg.EnablePadding {
		paddingStatus = fmt.Sprintf("已启用 (%s)", cfg.PaddingDistribution)
	}
	fmt.Printf("║  Padding: %-46s ║\n", paddingStatus)
	
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  按 Ctrl+C 停止  |  --stats 查看统计                         ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func printStats() {
	stats := metrics.GetStats()
	fmt.Println()
	fmt.Println("══════════════════ 统计信息 ══════════════════")
	fmt.Println(stats.String())
	fmt.Println("═══════════════════════════════════════════════")
}



