

//pkg/config/config.go
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

	// 性能调优
	MaxStreamsPerConn int           `yaml:"max_streams_per_conn"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`

	// 日志
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

// Validate 验证服务端配置
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

	// 检查证书文件是否存在
	if _, err := os.Stat(c.CertFile); os.IsNotExist(err) {
		return fmt.Errorf("certificate file not found: %s", c.CertFile)
	}
	if _, err := os.Stat(c.KeyFile); os.IsNotExist(err) {
		return fmt.Errorf("key file not found: %s", c.KeyFile)
	}

	if c.WSPath == "" {
		c.WSPath = "/ws"
	}

	// 确保路径以 / 开头
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
	Socks5Auth   string `yaml:"socks5_auth"` // user:pass

	// 连接池
	NumConnections int           `yaml:"num_connections"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`

	// TLS
	Insecure bool `yaml:"insecure"`

	// ECH
	EnableECH bool   `yaml:"enable_ech"`
	ECHDomain string `yaml:"ech_domain"`
	ECHDns    string `yaml:"ech_dns"`

	// Padding 配置
	EnablePadding       bool   `yaml:"enable_padding"`
	PaddingMinSize      int    `yaml:"padding_min_size"`
	PaddingMaxSize      int    `yaml:"padding_max_size"`
	PaddingDistribution string `yaml:"padding_distribution"` // uniform, normal, mimicry

	// IP 策略
	IPStrategy string `yaml:"ip_strategy"` // 4, 6, 4,6, 6,4

	// 日志
	LogLevel string `yaml:"log_level"`
}

func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Socks5Listen:        ":1080",
		NumConnections:      3,
		WriteTimeout:        10 * time.Second,
		ReadTimeout:         60 * time.Second,
		EnableECH:           true,
		ECHDomain:           "cloudflare-ech.com",
		ECHDns:              "https://doh.pub/dns-query",
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

// Validate 验证客户端配置
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

	if c.PaddingMinSize < 0 {
		c.PaddingMinSize = 64
	}
	if c.PaddingMaxSize < c.PaddingMinSize {
		c.PaddingMaxSize = c.PaddingMinSize + 192
	}

	// 验证 Padding 分布
	switch c.PaddingDistribution {
	case "uniform", "normal", "mimicry", "":
		// 有效
	default:
		c.PaddingDistribution = "mimicry"
	}

	// 验证 IP 策略
	switch c.IPStrategy {
	case "", "4", "6", "4,6", "6,4":
		// 有效
	default:
		c.IPStrategy = ""
	}

	return nil
}


