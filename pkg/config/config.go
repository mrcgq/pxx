package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ==================== 服务端配置 ====================

type ServerConfig struct {
	Listen   string `yaml:"listen"`
	CertFile string `yaml:"cert"`
	KeyFile  string `yaml:"key"`
	Token    string `yaml:"token"`
	WSPath   string `yaml:"ws_path"`

	MaxStreamsPerConn int           `yaml:"max_streams_per_conn"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`

	LogLevel string `yaml:"log_level"`
}

func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Listen:            ":443",
		CertFile:          "cert.pem",
		KeyFile:           "key.pem",
		WSPath:            "/ws",
		MaxStreamsPerConn: 1000,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		LogLevel:          "info",
	}
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	if path == "" {
		return DefaultServerConfig(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultServerConfig(), err
	}

	cfg := DefaultServerConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *ServerConfig) Validate() error {
	if c.Listen == "" {
		c.Listen = ":443"
	}

	if c.CertFile == "" {
		return errors.New("TLS certificate file is required")
	}
	if c.KeyFile == "" {
		return errors.New("TLS key file is required")
	}

	if _, err := os.Stat(c.CertFile); os.IsNotExist(err) {
		return fmt.Errorf("certificate file not found: %s", c.CertFile)
	}
	if _, err := os.Stat(c.KeyFile); os.IsNotExist(err) {
		return fmt.Errorf("key file not found: %s", c.KeyFile)
	}

	if c.WSPath == "" {
		c.WSPath = "/ws"
	}
	if c.WSPath[0] != '/' {
		c.WSPath = "/" + c.WSPath
	}

	if c.MaxStreamsPerConn <= 0 {
		c.MaxStreamsPerConn = 1000
	}
	if c.MaxStreamsPerConn > 10000 {
		c.MaxStreamsPerConn = 10000
	}

	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 60 * time.Second
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = 10 * time.Second
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 120 * time.Second
	}

	return nil
}

// ==================== 客户端配置 ====================

type ClientConfig struct {
	Server   string `yaml:"server"`
	Token    string `yaml:"token"`
	ClientID string `yaml:"client_id"`

	// SOCKS5
	Socks5Listen string `yaml:"socks5_listen"`
	Socks5Auth   string `yaml:"socks5_auth"`

	// 连接池
	NumConnections int           `yaml:"num_connections"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`

	// TLS
	Insecure bool `yaml:"insecure"`

	// uTLS 指纹伪装
	EnableUTLS  bool   `yaml:"enable_utls"`
	Fingerprint string `yaml:"fingerprint"` // chrome, firefox, safari, ios, android, random

	// ECH
	EnableECH bool   `yaml:"enable_ech"`
	ECHDomain string `yaml:"ech_domain"`
	ECHDns    string `yaml:"ech_dns"`

	// Argo 隧道
	EnableArgo        bool   `yaml:"enable_argo"`
	ArgoMode          string `yaml:"argo_mode"`           // "auto", "always", "fallback"
	ArgoLocalPort     int    `yaml:"argo_local_port"`     // 隧道本地端口，0=随机
	CloudflaredPath   string `yaml:"cloudflared_path"`    // cloudflared 路径
	AutoInstallCFD    bool   `yaml:"auto_install_cfd"`    // 自动安装 cloudflared

	// Cloudflare IP 优选
	EnableCFOptimize    bool          `yaml:"enable_cf_optimize"`
	CFOptimizeCount     int           `yaml:"cf_optimize_count"`
	CFOptimizeInterval  time.Duration `yaml:"cf_optimize_interval"`
	CFOptimizeConcurrency int         `yaml:"cf_optimize_concurrency"`
	PreferredCFIP       string        `yaml:"preferred_cf_ip"` // 手动指定

	// Padding 配置
	EnablePadding       bool   `yaml:"enable_padding"`
	PaddingMinSize      int    `yaml:"padding_min_size"`
	PaddingMaxSize      int    `yaml:"padding_max_size"`
	PaddingDistribution string `yaml:"padding_distribution"`

	// IP 策略
	IPStrategy string `yaml:"ip_strategy"`

	// 日志
	LogLevel string `yaml:"log_level"`
}

func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Socks5Listen:        ":1080",
		NumConnections:      3,
		WriteTimeout:        10 * time.Second,
		ReadTimeout:         60 * time.Second,
		EnableUTLS:          true,
		Fingerprint:         "chrome",
		EnableECH:           false, // 默认关闭，uTLS 优先
		ECHDomain:           "cloudflare-ech.com",
		ECHDns:              "https://doh.pub/dns-query",
		EnableArgo:          false,
		ArgoMode:            "fallback", // 默认回落模式
		ArgoLocalPort:       0,
		AutoInstallCFD:      true,
		EnableCFOptimize:    true,
		CFOptimizeCount:     200,
		CFOptimizeInterval:  30 * time.Minute,
		CFOptimizeConcurrency: 50,
		EnablePadding:       true,
		PaddingMinSize:      64,
		PaddingMaxSize:      256,
		PaddingDistribution: "mimicry",
		IPStrategy:          "",
		LogLevel:            "info",
	}
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	if path == "" {
		return DefaultClientConfig(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultClientConfig(), err
	}

	cfg := DefaultClientConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *ClientConfig) Validate() error {
	if c.Server == "" {
		return errors.New("server address is required")
	}

	u, err := url.Parse(c.Server)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}

	if u.Scheme != "wss" && u.Scheme != "ws" {
		return errors.New("server URL must use ws:// or wss:// scheme")
	}

	if u.Host == "" {
		return errors.New("server URL must include host")
	}

	if u.Path == "" {
		c.Server = c.Server + "/ws"
	}

	if c.Socks5Listen == "" {
		c.Socks5Listen = ":1080"
	}

	if c.NumConnections < 1 {
		c.NumConnections = 1
	}
	if c.NumConnections > 10 {
		c.NumConnections = 10
	}

	if c.WriteTimeout <= 0 {
		c.WriteTimeout = 10 * time.Second
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 60 * time.Second
	}

	// uTLS 指纹验证
	switch c.Fingerprint {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "":
		// 有效
	default:
		c.Fingerprint = "chrome"
	}

	// Argo 模式验证
	switch c.ArgoMode {
	case "auto", "always", "fallback", "":
		// 有效
	default:
		c.ArgoMode = "fallback"
	}

	if c.CFOptimizeCount < 10 {
		c.CFOptimizeCount = 10
	}
	if c.CFOptimizeCount > 1000 {
		c.CFOptimizeCount = 1000
	}

	if c.CFOptimizeConcurrency < 10 {
		c.CFOptimizeConcurrency = 10
	}
	if c.CFOptimizeConcurrency > 100 {
		c.CFOptimizeConcurrency = 100
	}

	if c.PaddingMinSize < 0 {
		c.PaddingMinSize = 64
	}
	if c.PaddingMaxSize < c.PaddingMinSize {
		c.PaddingMaxSize = c.PaddingMinSize + 192
	}

	switch c.PaddingDistribution {
	case "uniform", "normal", "mimicry", "":
		// 有效
	default:
		c.PaddingDistribution = "mimicry"
	}

	switch c.IPStrategy {
	case "", "4", "6", "4,6", "6,4":
		// 有效
	default:
		c.IPStrategy = ""
	}

	return nil
}
