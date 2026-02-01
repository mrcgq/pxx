package ech

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	echListMu    sync.RWMutex
	echList      []byte
	echDomain    string
	echDNSServer string
)

const (
	typeHTTPS       = 65
	ECHRetryDelay   = 2 * time.Second
	ECHRefreshDelay = 24 * time.Hour
)

// Prepare 初始化 ECH 配置
func Prepare(domain, dnsServer string) error {
	echListMu.Lock()
	echDomain = domain
	echDNSServer = dnsServer
	echListMu.Unlock()

	return refreshECH()
}

// refreshECH 刷新 ECH 配置
func refreshECH() error {
	echListMu.RLock()
	domain := echDomain
	dnsServer := echDNSServer
	echListMu.RUnlock()

	for retry := 0; retry < 3; retry++ {
		echBase64, err := queryHTTPSRecord(domain, dnsServer)
		if err != nil {
			time.Sleep(ECHRetryDelay)
			continue
		}
		if echBase64 == "" {
			time.Sleep(ECHRetryDelay)
			continue
		}

		raw, err := base64.StdEncoding.DecodeString(echBase64)
		if err != nil {
			time.Sleep(ECHRetryDelay)
			continue
		}

		echListMu.Lock()
		echList = raw
		echListMu.Unlock()
		return nil
	}
	return errors.New("failed to get ECH config")
}

// StartAutoRefresh 启动自动刷新
func StartAutoRefresh(stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(ECHRefreshDelay)
		defer ticker.Stop()

		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				_ = refreshECH()
			}
		}
	}()
}

// Refresh 手动刷新 ECH 配置
func Refresh() error {
	return refreshECH()
}

// IsConfigured 检查是否已配置 ECH
func IsConfigured() bool {
	echListMu.RLock()
	defer echListMu.RUnlock()
	return len(echList) > 0
}

// BuildTLSConfig 构建支持 ECH 的 TLS 配置
func BuildTLSConfig(serverName string, insecure bool) (*tls.Config, error) {
	echListMu.RLock()
	ech := echList
	echListMu.RUnlock()

	if len(ech) == 0 {
		return &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         serverName,
			InsecureSkipVerify: insecure,
		}, nil
	}

	roots, _ := x509.SystemCertPool()

	return &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     serverName,
		EncryptedClientHelloConfigList: ech,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("ECH rejected")
		},
		RootCAs:            roots,
		InsecureSkipVerify: insecure,
	}, nil
}

func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	if strings.HasPrefix(dnsServer, "http://") || strings.HasPrefix(dnsServer, "https://") {
		return queryDoH(domain, dnsServer)
	}
	return queryDNSUDP(domain, dnsServer)
}

func queryDNSUDP(domain, dnsServer string) (string, error) {
	if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}
	query := buildDNSQuery(domain, typeHTTPS)
	conn, err := net.DialTimeout("udp", dnsServer, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}

	if _, err := conn.Write(query); err != nil {
		return "", fmt.Errorf("write DNS query: %w", err)
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return "", err
	}
	return parseDNSResponse(response[:n])
}

func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	q.Set("dns", base64.RawURLEncoding.EncodeToString(dnsQuery))
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0x00)
	query = append(query, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("response too short")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", nil
	}

	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5

	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)
		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}
