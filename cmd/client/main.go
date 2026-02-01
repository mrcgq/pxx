

//cmd/client/main.go

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"phantom-x/internal/ech"
	"phantom-x/internal/pool"
	"phantom-x/internal/proto"
	"phantom-x/internal/socks5"
	"phantom-x/internal/stream"
	"phantom-x/pkg/config"
	plog "phantom-x/pkg/log"
	"phantom-x/pkg/metrics"
)

var (
	Version   = "1.0.0"
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
	noECH := flag.Bool("no-ech", false, "禁用ECH")

	flag.Parse()

	if *showVersion {
		fmt.Printf("Phantom-X Client v%s\n", Version)
		fmt.Printf("  Build: %s\n", BuildTime)
		fmt.Printf("  Commit: %s\n", GitCommit)
		return
	}

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		plog.Warn("Load config failed, using defaults: %v", err)
		cfg = config.DefaultClientConfig()
	}

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
	if *noECH {
		cfg.EnableECH = false
	}

	if err := cfg.Validate(); err != nil {
		plog.Fatalf("Config validation failed: %v", err)
	}

	plog.SetLevel(cfg.LogLevel)

	if cfg.ClientID == "" {
		cfg.ClientID = uuid.NewString()
	}

	var echStopCh chan struct{}
	if cfg.EnableECH && !cfg.Insecure {
		plog.Info("Preparing ECH...")
		if err := ech.Prepare(cfg.ECHDomain, cfg.ECHDns); err != nil {
			plog.Warn("ECH prepare failed, falling back to TLS: %v", err)
			cfg.EnableECH = false
		} else {
			echStopCh = make(chan struct{})
			ech.StartAutoRefresh(echStopCh)
			plog.Debug("ECH auto-refresh started")
		}
	}

	streamMgr := stream.NewManager()

	poolCfg := &pool.Config{
		ServerURL:         cfg.Server,
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
		EnableECH:         cfg.EnableECH,
		ECHDomain:         cfg.ECHDomain,
		ECHDns:            cfg.ECHDns,
		EnablePadding:     cfg.EnablePadding,
		PaddingMinSize:    cfg.PaddingMinSize,
		PaddingMaxSize:    cfg.PaddingMaxSize,
		PaddingDistribute: cfg.PaddingDistribution,
	}

	connPool := pool.NewConnPool(poolCfg)

	// 创建 SOCKS5 服务器（需要先创建，以便在 frameHandler 中使用）
	socks5Server := socks5.NewServer(cfg, streamMgr)

	// 设置帧处理器，传入 socks5Server 以处理 UDP 响应
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

	printBanner(cfg)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	plog.Info("Shutting down...")
	if echStopCh != nil {
		close(echStopCh)
	}
	socks5Server.Stop()
	connPool.Stop()
	streamMgr.CloseAll()

	if *showStats {
		printStats()
	}
}

// handleServerFrame 处理服务端返回的帧
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
			// UDP 响应：通过 SOCKS5 服务器发送给客户端
			if err := socks5Srv.HandleUDPResponse(streamID, payload); err != nil {
				plog.Debug("[Client] Failed to handle UDP response for stream %d: %v", streamID, err)
			}
		} else {
			// TCP 数据：写入流的数据通道
			if err := st.SendData(payload); err != nil {
				plog.Debug("[Client] Failed to send data to stream %d: %v", streamID, err)
			}
		}

	case proto.CmdClose:
		plog.Debug("[Client] Stream %d closed by server", streamID)
		
		// 检查是否是 UDP 流，如果是则清理 UDP 会话
		st := mgr.Get(streamID)
		if st != nil && st.IsUDP {
			socks5Srv.HandleUDPClose(streamID)
		}
		
		mgr.Unregister(streamID)

	case proto.CmdPing:
		// 服务端发来的 Ping，可以忽略或记录
		plog.Debug("[Client] Received ping from server")

	case proto.CmdPong:
		// Pong 响应，通常由底层连接处理
		plog.Debug("[Client] Received pong from server")

	default:
		plog.Debug("[Client] Unknown command %d for stream %d", cmd, streamID)
	}
}

func printBanner(cfg *config.ClientConfig) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║              Phantom-X Client v1.0                       ║")
	fmt.Println("║              高性能 · 抗探测 · 0-RTT                      ║")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Printf("║  服务器: %-47s ║\n", cfg.Server)
	fmt.Printf("║  SOCKS5: %-47s ║\n", cfg.Socks5Listen)
	fmt.Printf("║  连接数: %-47d ║\n", cfg.NumConnections)
	echStatus := "已禁用"
	if cfg.EnableECH {
		echStatus = "已启用"
	}
	fmt.Printf("║  ECH:    %-47s ║\n", echStatus)
	paddingStatus := "已禁用"
	if cfg.EnablePadding {
		paddingStatus = "已启用"
	}
	fmt.Printf("║  Padding: %-46s ║\n", paddingStatus)
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Println("║  按 Ctrl+C 停止  |  --stats 查看统计                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func printStats() {
	stats := metrics.GetStats()
	fmt.Println()
	fmt.Println("══════════════════ 统计信息 ══════════════════")
	fmt.Println(stats.String())
	fmt.Println("═══════════════════════════════════════════════")
}



