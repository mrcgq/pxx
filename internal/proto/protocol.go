

//internal/proto/protocol.go

package proto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ==================== 常量定义 ====================

const (
	HeaderLen   = 8
	MaxPayload  = 65535
	MaxInitData = 4096
	MaxPadding  = 512
	MaxHostLen  = 253 // DNS 规范最大域名长度
)

// 命令类型
const (
	CmdOpenTCP    byte = 0x01
	CmdOpenUDP    byte = 0x02
	CmdData       byte = 0x03
	CmdClose      byte = 0x04
	CmdConnStatus byte = 0x05
	CmdPing       byte = 0x06
	CmdPong       byte = 0x07
)

// 标志位
const (
	FlagPadding   byte = 0x01
	FlagAggregate byte = 0x02
	FlagEncrypted byte = 0x04
)

// 状态码
const (
	StatusOK   byte = 0x00
	StatusFail byte = 0x01
)

// IP 策略
const (
	IPDefault byte = 0x00
	IPv4Only  byte = 0x01
	IPv6Only  byte = 0x02
	IPv4First byte = 0x03
	IPv6First byte = 0x04
)

// 错误定义
var (
	ErrFrameTooShort   = errors.New("frame too short")
	ErrInvalidLength   = errors.New("invalid length")
	ErrPayloadTooLarge = errors.New("payload too large")
	ErrInvalidHost     = errors.New("invalid host")
	ErrHostTooLong     = errors.New("host too long")
	ErrEmptyHost       = errors.New("empty host")
	ErrInvalidPort     = errors.New("invalid port")
)

// ==================== 帧结构 ====================

type Frame struct {
	Cmd      byte
	StreamID uint32
	Flags    byte
	Payload  []byte
}

// ==================== 基础编解码 ====================

// PackHeader 打包帧头部
func PackHeader(buf []byte, cmd byte, streamID uint32, flags byte, length int) {
	buf[0] = cmd
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	buf[5] = flags
	binary.BigEndian.PutUint16(buf[6:8], uint16(length))
}

// UnpackHeader 解包帧头部
func UnpackHeader(buf []byte) (cmd byte, streamID uint32, flags byte, length int) {
	cmd = buf[0]
	streamID = binary.BigEndian.Uint32(buf[1:5])
	flags = buf[5]
	length = int(binary.BigEndian.Uint16(buf[6:8]))
	return
}

// PackFrame 打包帧
func PackFrame(buf []byte, cmd byte, streamID uint32, flags byte, payload []byte, _ int) int {
	PackHeader(buf, cmd, streamID, flags, len(payload))
	copy(buf[HeaderLen:], payload)
	return HeaderLen + len(payload)
}

// PackFrameAlloc 分配并打包帧
func PackFrameAlloc(cmd byte, streamID uint32, payload []byte) []byte {
	buf := make([]byte, HeaderLen+len(payload))
	PackHeader(buf, cmd, streamID, 0, len(payload))
	copy(buf[HeaderLen:], payload)
	return buf
}

// ==================== 地址格式化（IPv6 安全）====================

// FormatHostPort 正确格式化主机和端口，支持 IPv6
// IPv4: 192.168.1.1:443
// IPv6: [::1]:443
// 域名: example.com:443
func FormatHostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// ParseHostPort 解析主机和端口，支持 IPv6
func ParseHostPort(hostport string) (host string, port uint16, err error) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}

	portNum, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return "", 0, ErrInvalidPort
	}

	return h, uint16(portNum), nil
}

// FormatAddress 格式化地址用于拨号
// 确保 IPv6 地址被正确包裹在方括号中
func FormatAddress(host string, port uint16) string {
	// 检查是否是 IPv6 地址
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() == nil {
		// IPv6 地址需要用方括号包裹
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// ==================== Host 验证 ====================

// 危险字符正则表达式
var (
	// 匹配可能导致注入的字符
	dangerousCharsRegex = regexp.MustCompile(`[\x00-\x1f\x7f<>\"'` + "`" + `\\\$\{\}\|\&\;\(\)\[\]]`)

	// 有效域名标签正则
	validLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

	// 有效 IPv4 地址
	ipv4Regex = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
)

// ValidateHost 严格验证 Host 地址
// 返回 nil 表示验证通过
func ValidateHost(host string) error {
	// 检查空值
	if len(host) == 0 {
		return ErrEmptyHost
	}

	// 检查长度
	if len(host) > MaxHostLen {
		return ErrHostTooLong
	}

	// 去除首尾空白
	host = strings.TrimSpace(host)
	if len(host) == 0 {
		return ErrEmptyHost
	}

	// 检查危险字符（可能导致注入攻击）
	if dangerousCharsRegex.MatchString(host) {
		return fmt.Errorf("%w: contains dangerous characters", ErrInvalidHost)
	}

	// 检查是否包含空白字符
	for _, r := range host {
		if unicode.IsSpace(r) {
			return fmt.Errorf("%w: contains whitespace", ErrInvalidHost)
		}
	}

	// 检查是否以点开头或结尾
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return fmt.Errorf("%w: invalid dot placement", ErrInvalidHost)
	}

	// 检查连续的点
	if strings.Contains(host, "..") {
		return fmt.Errorf("%w: consecutive dots", ErrInvalidHost)
	}

	// 尝试解析为 IP 地址
	if ip := net.ParseIP(host); ip != nil {
		// 有效的 IPv4 或 IPv6 地址
		return nil
	}

	// 检查是否是带方括号的 IPv6
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		ipStr := host[1 : len(host)-1]
		if ip := net.ParseIP(ipStr); ip != nil {
			return nil
		}
		return fmt.Errorf("%w: invalid bracketed IPv6", ErrInvalidHost)
	}

	// 验证为域名
	return validateDomain(host)
}

// validateDomain 验证域名格式
func validateDomain(domain string) error {
	// 分割标签
	labels := strings.Split(domain, ".")

	if len(labels) < 1 {
		return fmt.Errorf("%w: no labels", ErrInvalidHost)
	}

	for i, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("%w: empty label", ErrInvalidHost)
		}

		if len(label) > 63 {
			return fmt.Errorf("%w: label too long", ErrInvalidHost)
		}

		// 检查标签格式
		// 允许数字开头（如 3com.com）但最后一个标签（TLD）不能全是数字
		if i == len(labels)-1 {
			// TLD 不能全是数字
			allDigits := true
			for _, r := range label {
				if !unicode.IsDigit(r) {
					allDigits = false
					break
				}
			}
			if allDigits {
				return fmt.Errorf("%w: TLD cannot be all digits", ErrInvalidHost)
			}
		}

		// 标签只能包含字母、数字和连字符
		for j, r := range label {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
				return fmt.Errorf("%w: invalid character in label", ErrInvalidHost)
			}
			// 连字符不能在开头或结尾
			if r == '-' && (j == 0 || j == len(label)-1) {
				return fmt.Errorf("%w: hyphen at label boundary", ErrInvalidHost)
			}
		}
	}

	return nil
}

// ValidateHostStrict 更严格的 Host 验证（用于安全敏感场景）
func ValidateHostStrict(host string) error {
	if err := ValidateHost(host); err != nil {
		return err
	}

	// 额外检查：禁止本地地址
	if isLocalAddress(host) {
		return fmt.Errorf("%w: local addresses not allowed", ErrInvalidHost)
	}

	return nil
}

// isLocalAddress 检查是否是本地/保留地址
func isLocalAddress(host string) bool {
	// 检查常见的本地主机名
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "localhost.localdomain" {
		return true
	}

	// 检查 IP 地址
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// 检查是否是回环地址
	if ip.IsLoopback() {
		return true
	}

	// 检查是否是私有地址
	if ip.IsPrivate() {
		return true
	}

	// 检查是否是链路本地地址
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	return false
}

// SanitizeHost 清理并验证 Host，返回安全的版本
func SanitizeHost(host string) (string, error) {
	// 去除首尾空白
	host = strings.TrimSpace(host)

	// 转换为小写（域名不区分大小写）
	// 注意：不对 IP 地址进行小写转换
	if net.ParseIP(host) == nil {
		host = strings.ToLower(host)
	}

	// 验证
	if err := ValidateHost(host); err != nil {
		return "", err
	}

	return host, nil
}

// ==================== Padding 配置 ====================

type PaddingConfig struct {
	Enabled       bool
	MinSize       int
	MaxPadding    int
	Distribution  string
	MimicryTarget string
}

func DefaultPaddingConfig() *PaddingConfig {
	return &PaddingConfig{
		Enabled:       true,
		MinSize:       64,
		MaxPadding:    256,
		Distribution:  "mimicry",
		MimicryTarget: "https",
	}
}

// ==================== Padding 计算器 ====================

type PaddingCalculator struct {
	cfg               *PaddingConfig
	rng               *mrand.Rand
	httpsSmallPktProb float64
	httpsSmallPktMean float64
	httpsSmallPktStd  float64
	httpsLargePktMean float64
	httpsLargePktStd  float64
}

func NewPaddingCalculator(cfg *PaddingConfig) *PaddingCalculator {
	return &PaddingCalculator{
		cfg:               cfg,
		rng:               mrand.New(mrand.NewSource(time.Now().UnixNano())),
		httpsSmallPktProb: 0.3,
		httpsSmallPktMean: 60,
		httpsSmallPktStd:  20,
		httpsLargePktMean: 1200,
		httpsLargePktStd:  400,
	}
}

func (p *PaddingCalculator) CalculatePadding(currentSize int) int {
	if !p.cfg.Enabled {
		return 0
	}

	switch p.cfg.Distribution {
	case "uniform":
		return p.uniformPadding(currentSize)
	case "normal":
		return p.normalPadding(currentSize)
	case "mimicry":
		return p.mimicryPadding(currentSize)
	default:
		return p.uniformPadding(currentSize)
	}
}

func (p *PaddingCalculator) uniformPadding(currentSize int) int {
	if currentSize >= p.cfg.MinSize {
		return p.rng.Intn(p.cfg.MaxPadding / 4)
	}
	base := p.cfg.MinSize - currentSize
	extra := p.rng.Intn(p.cfg.MaxPadding / 2)
	padding := base + extra
	if padding > p.cfg.MaxPadding {
		padding = p.cfg.MaxPadding
	}
	return padding
}

func (p *PaddingCalculator) normalPadding(currentSize int) int {
	mean := float64(p.cfg.MaxPadding) / 2
	std := float64(p.cfg.MaxPadding) / 4
	padding := int(p.rng.NormFloat64()*std + mean)
	if padding < 0 {
		padding = 0
	}
	if padding > p.cfg.MaxPadding {
		padding = p.cfg.MaxPadding
	}
	return padding
}

func (p *PaddingCalculator) mimicryPadding(currentSize int) int {
	var targetSize int
	if p.rng.Float64() < p.httpsSmallPktProb {
		targetSize = int(p.rng.NormFloat64()*p.httpsSmallPktStd + p.httpsSmallPktMean)
	} else {
		targetSize = int(p.rng.NormFloat64()*p.httpsLargePktStd + p.httpsLargePktMean)
	}
	if targetSize < p.cfg.MinSize {
		targetSize = p.cfg.MinSize
	}
	if targetSize > 1500 {
		targetSize = 1500
	}
	padding := targetSize - currentSize
	if padding < 0 {
		padding = 0
	}
	if padding > p.cfg.MaxPadding {
		padding = p.cfg.MaxPadding
	}
	return padding
}

// ==================== 带 Padding 的编解码 ====================

// PackFrameWithPadding 编码帧并添加填充
// 格式: [Header][Payload][Padding][PaddingLen]
// PaddingLen 放在最后一个字节，便于解析
func PackFrameWithPadding(buf []byte, cmd byte, streamID uint32, flags byte, payload []byte, paddingCalc *PaddingCalculator) int {
	currentSize := HeaderLen + len(payload)
	paddingLen := 0

	if paddingCalc != nil {
		paddingLen = paddingCalc.CalculatePadding(currentSize)
	}

	// 只有在真正添加 padding 时才设置标志位
	if paddingLen > 0 {
		flags |= FlagPadding
	}

	// 计算总 payload 长度
	totalPayloadLen := len(payload)
	if paddingLen > 0 {
		totalPayloadLen += paddingLen + 1 // padding 内容 + paddingLen 字节
	}

	PackHeader(buf, cmd, streamID, flags, totalPayloadLen)
	offset := HeaderLen

	// 写入原始 payload
	if len(payload) > 0 {
		copy(buf[offset:], payload)
		offset += len(payload)
	}

	// 写入 padding（只有 paddingLen > 0 时才写入）
	if paddingLen > 0 {
		// 先写 padding 内容
		generatePadding(buf[offset:offset+paddingLen], paddingLen)
		offset += paddingLen
		// 最后写 paddingLen（1字节）
		buf[offset] = byte(paddingLen)
		offset++
	}

	return offset
}

// generatePadding 生成混淆填充数据
func generatePadding(buf []byte, length int) {
	if length <= 0 {
		return
	}

	// 模拟 HTTP/TLS 流量特征的字符集
	httpChars := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~:/?#[]@!$&'()*+,;= \r\n")

	// 前半部分用随机二进制数据
	halfLen := length / 2
	if halfLen > 0 {
		rand.Read(buf[:halfLen])
	}

	// 后半部分用类 HTTP 字符（增加混淆效果）
	for i := halfLen; i < length; i++ {
		buf[i] = httpChars[mrand.Intn(len(httpChars))]
	}
}

func RemovePadding(payload []byte) []byte {
	if len(payload) < 1 {
		return payload
	}

	// paddingLen 在最后一个字节
	paddingLen := int(payload[len(payload)-1])

	// paddingLen == 0 是异常情况
	// 正常流程中只有 paddingLen > 0 才会设置 FlagPadding
	// 如果收到这种数据，可能是攻击或数据损坏，返回原数据不做修改
	if paddingLen == 0 {
		return payload  // ✅ 不修改，返回原数据
	}

	// 验证 paddingLen 合理性
	if paddingLen > MaxPadding {
		return payload
	}

	// 检查长度是否足够：需要至少 paddingLen + 1（paddingLen字节本身）
	if paddingLen+1 > len(payload) {
		return payload
	}

	// 计算真实 payload 结束位置
	realEnd := len(payload) - 1 - paddingLen
	if realEnd < 0 {
		return payload
	}

	return payload[:realEnd]
}

// UnpackFrameWithPadding 解码带填充的帧
func UnpackFrameWithPadding(data []byte) (cmd byte, streamID uint32, flags byte, payload []byte, err error) {
	if len(data) < HeaderLen {
		return 0, 0, 0, nil, ErrFrameTooShort
	}

	cmd, streamID, flags, length := UnpackHeader(data[:HeaderLen])

	if len(data) < HeaderLen+length {
		return 0, 0, 0, nil, ErrInvalidLength
	}

	rawPayload := data[HeaderLen : HeaderLen+length]

	// 只有设置了 FlagPadding 才尝试移除 padding
	if flags&FlagPadding != 0 && len(rawPayload) > 0 {
		payload = RemovePadding(rawPayload)
	} else {
		payload = rawPayload
	}

	return cmd, streamID, flags, payload, nil
}

// ==================== Open Payload ====================

// BuildOpenPayload 构建 Open 命令的 payload
func BuildOpenPayload(ipStrategy byte, host string, port uint16, initData []byte) []byte {
	buf := make([]byte, 1+1+len(host)+2+len(initData))
	buf[0] = ipStrategy
	buf[1] = byte(len(host))
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+len(host):], port)
	copy(buf[4+len(host):], initData)
	return buf
}

// ParseOpenPayload 解析 Open 命令的 payload
func ParseOpenPayload(payload []byte) (ipStrategy byte, host string, port uint16, initData []byte, err error) {
	if len(payload) < 4 {
		err = errors.New("payload too short")
		return
	}

	ipStrategy = payload[0]
	hostLen := int(payload[1])

	if hostLen > MaxHostLen {
		err = ErrHostTooLong
		return
	}

	if len(payload) < 4+hostLen {
		err = errors.New("invalid host length")
		return
	}

	host = string(payload[2 : 2+hostLen])

	// 验证 host 格式
	if err = ValidateHost(host); err != nil {
		return
	}

	port = binary.BigEndian.Uint16(payload[2+hostLen : 4+hostLen])
	initData = payload[4+hostLen:]
	return
}

// ==================== 聚合数据 ====================

type AggregatedData struct {
	Items []struct {
		StreamID uint32
		Data     []byte
	}
}

func (a *AggregatedData) Encode() []byte {
	size := 0
	for _, item := range a.Items {
		size += 4 + 2 + len(item.Data)
	}
	buf := make([]byte, size)
	offset := 0
	for _, item := range a.Items {
		binary.BigEndian.PutUint32(buf[offset:], item.StreamID)
		binary.BigEndian.PutUint16(buf[offset+4:], uint16(len(item.Data)))
		copy(buf[offset+6:], item.Data)
		offset += 6 + len(item.Data)
	}
	return buf
}

// Reset 重置聚合数据，保留底层容量
func (a *AggregatedData) Reset() {
	// 清除对数据的引用，避免内存泄漏
	for i := range a.Items {
		a.Items[i].StreamID = 0
		a.Items[i].Data = nil
	}
	a.Items = a.Items[:0]
}

// DecodeAggregatedData 解码聚合数据
func DecodeAggregatedData(data []byte) (*AggregatedData, error) {
	agg := &AggregatedData{}
	offset := 0
	for offset < len(data) {
		if offset+6 > len(data) {
			break
		}
		streamID := binary.BigEndian.Uint32(data[offset:])
		dataLen := int(binary.BigEndian.Uint16(data[offset+4:]))
		offset += 6
		if offset+dataLen > len(data) {
			break
		}
		agg.Items = append(agg.Items, struct {
			StreamID uint32
			Data     []byte
		}{streamID, data[offset : offset+dataLen]})
		offset += dataLen
	}
	return agg, nil
}



