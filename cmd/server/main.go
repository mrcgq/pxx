

//cmd/server/main.go

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"phantom-x/internal/server"
	"phantom-x/internal/stream"
	"phantom-x/internal/transport"
	"phantom-x/pkg/config"
	plog "phantom-x/pkg/log"
	"phantom-x/pkg/metrics"
)

var (
	Version   = "1.0.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
	startTime = time.Now()
)

func main() {
	configPath := flag.String("c", "", "配置文件路径")
	showVersion := flag.Bool("v", false, "显示版本")

	listenAddr := flag.String("l", "", "监听地址")
	certFile := flag.String("cert", "", "TLS证书")
	keyFile := flag.String("key", "", "TLS私钥")
	token := flag.String("token", "", "认证令牌")
	wsPath := flag.String("path", "", "WebSocket路径")

	flag.Parse()

	if *showVersion {
		fmt.Printf("Phantom-X Server v%s\n", Version)
		fmt.Printf("  Build: %s\n", BuildTime)
		fmt.Printf("  Commit: %s\n", GitCommit)
		return
	}

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		plog.Fatalf("Load config failed: %v", err)
	}

	if *listenAddr != "" {
		cfg.Listen = *listenAddr
	}
	if *certFile != "" {
		cfg.CertFile = *certFile
	}
	if *keyFile != "" {
		cfg.KeyFile = *keyFile
	}
	if *token != "" {
		cfg.Token = *token
	}
	if *wsPath != "" {
		cfg.WSPath = *wsPath
	}

	if err := cfg.Validate(); err != nil {
		plog.Fatalf("Config validation failed: %v", err)
	}

	plog.SetLevel(cfg.LogLevel)

	srv := NewServer(cfg)

	if err := srv.Start(); err != nil {
		plog.Fatalf("Start failed: %v", err)
	}

	printBanner(cfg)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	plog.Info("Shutting down...")
	srv.Stop()
}

type Server struct {
	cfg      *config.ServerConfig
	upgrader *transport.Upgrader
	httpSrv  *http.Server
}

func NewServer(cfg *config.ServerConfig) *Server {
	return &Server{
		cfg:      cfg,
		upgrader: transport.NewUpgrader(cfg),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.WSPath, s.handleWebSocket)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/", s.handleIndex)

	cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load cert failed: %w", err)
	}

	s.httpSrv = &http.Server{
		Addr:    s.cfg.Listen,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadTimeout:  s.cfg.ReadTimeout,
		WriteTimeout: s.cfg.WriteTimeout,
		IdleTimeout:  s.cfg.IdleTimeout,
	}

	go func() {
		if err := s.httpSrv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			plog.Fatalf("HTTP server error: %v", err)
		}
	}()

	return nil
}

func (s *Server) Stop() {
	s.httpSrv.SetKeepAlivesEnabled(false)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.httpSrv.Shutdown(ctx); err != nil {
		plog.Error("Shutdown error: %v", err)
	}

	plog.Info("Server stopped gracefully")
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, clientID, err := s.upgrader.Upgrade(w, r)
	if err != nil {
		if err.Error() == "unauthorized" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
		return
	}

	plog.Info("[Server] Client connected: %s from %s", clientID, r.RemoteAddr)
	metrics.IncrActiveConnections()
	metrics.IncrTotalConnections()

	sessionStreamMgr := stream.NewManager()
	session := server.NewSession(clientID, conn, sessionStreamMgr, s.cfg)
	session.Serve()

	metrics.DecrActiveConnections()
	plog.Info("[Server] Client disconnected: %s", clientID)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>`))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	stats := metrics.GetStats()
	response := map[string]interface{}{
		"status":  "healthy",
		"version": Version,
		"uptime":  time.Since(startTime).String(),
		"stats": map[string]interface{}{
			"active_connections": stats.ActiveConnections,
			"total_connections":  stats.TotalConnections,
			"active_streams":     stats.ActiveStreams,
			"bytes_sent":         stats.BytesSent,
			"bytes_recv":         stats.BytesRecv,
		},
	}

	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(metrics.ExportPrometheus()))
}

func printBanner(cfg *config.ServerConfig) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║              Phantom-X Server v1.0                       ║")
	fmt.Println("║              高性能 · 抗探测 · 0-RTT                      ║")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Printf("║  监听: %-49s ║\n", cfg.Listen)
	fmt.Printf("║  路径: %-49s ║\n", cfg.WSPath)
	if cfg.Token != "" {
		fmt.Println("║  认证: 已启用 (HMAC签名)                                 ║")
	} else {
		fmt.Println("║  认证: 未启用                                            ║")
	}
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Println("║  健康检查: /health  |  监控指标: /metrics                 ║")
	fmt.Println("║  按 Ctrl+C 停止                                          ║")
	fmt.Println("╚══���═══════════════════════════════════════════════════════╝")
	fmt.Println()
}



