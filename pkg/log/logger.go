
//pkg/log/logger.go
package log

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// Level 日志级别
type Level int32

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

var (
	level      int32 = int32(INFO)
	logger     = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)
	mu         sync.RWMutex
	levelNames = map[Level]string{
		DEBUG: "DEBUG",
		INFO:  "INFO",
		WARN:  "WARN",
		ERROR: "ERROR",
	}
)

// SetLevel 设置日志级别
func SetLevel(l string) {
	var newLevel Level
	switch strings.ToLower(strings.TrimSpace(l)) {
	case "debug":
		newLevel = DEBUG
	case "warn", "warning":
		newLevel = WARN
	case "error", "err":
		newLevel = ERROR
	default:
		newLevel = INFO
	}
	atomic.StoreInt32(&level, int32(newLevel))
}

// GetLevel 获取当前日志级别
func GetLevel() Level {
	return Level(atomic.LoadInt32(&level))
}

// SetOutput 设置日志输出
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	logger = log.New(w, "", log.LstdFlags|log.Lshortfile)
}

// GetLevelName 获取级别名称
func GetLevelName(l Level) string {
	if name, ok := levelNames[l]; ok {
		return name
	}
	return "UNKNOWN"
}

// ParseLevel 解析日志级别字符串
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return DEBUG
	case "info":
		return INFO
	case "warn", "warning":
		return WARN
	case "error", "err":
		return ERROR
	default:
		return INFO
	}
}

// Debug 调试日志
func Debug(format string, v ...any) {
	if Level(atomic.LoadInt32(&level)) <= DEBUG {
		mu.RLock()
		defer mu.RUnlock()
		_ = logger.Output(2, fmt.Sprintf("[DEBUG] "+format, v...))
	}
}

// Info 信息日志
func Info(format string, v ...any) {
	if Level(atomic.LoadInt32(&level)) <= INFO {
		mu.RLock()
		defer mu.RUnlock()
		_ = logger.Output(2, fmt.Sprintf("[INFO] "+format, v...))
	}
}

// Warn 警告日志
func Warn(format string, v ...any) {
	if Level(atomic.LoadInt32(&level)) <= WARN {
		mu.RLock()
		defer mu.RUnlock()
		_ = logger.Output(2, fmt.Sprintf("[WARN] "+format, v...))
	}
}

// Error 错误日志
func Error(format string, v ...any) {
	if Level(atomic.LoadInt32(&level)) <= ERROR {
		mu.RLock()
		defer mu.RUnlock()
		_ = logger.Output(2, fmt.Sprintf("[ERROR] "+format, v...))
	}
}

// Printf 兼容标准log包
func Printf(format string, v ...any) {
	Info(format, v...)
}

// Println 兼容标准log包
func Println(v ...any) {
	Info("%s", fmt.Sprintln(v...))
}

// Fatalf 致命错误并退出
func Fatalf(format string, v ...any) {
	mu.RLock()
	_ = logger.Output(2, fmt.Sprintf("[FATAL] "+format, v...))
	mu.RUnlock()
	os.Exit(1)
}

// Fatal 致命错误并退出
func Fatal(v ...any) {
	mu.RLock()
	_ = logger.Output(2, fmt.Sprintf("[FATAL] %s", fmt.Sprint(v...)))
	mu.RUnlock()
	os.Exit(1)
}

// IsDebugEnabled 检查是否启用调试日志
func IsDebugEnabled() bool {
	return Level(atomic.LoadInt32(&level)) <= DEBUG
}

// IsInfoEnabled 检查是否启用信息日志
func IsInfoEnabled() bool {
	return Level(atomic.LoadInt32(&level)) <= INFO
}

// IsWarnEnabled 检查是否启用警告日志
func IsWarnEnabled() bool {
	return Level(atomic.LoadInt32(&level)) <= WARN
}

// IsErrorEnabled 检查是否启用错误日志
func IsErrorEnabled() bool {
	return Level(atomic.LoadInt32(&level)) <= ERROR
}

// PrefixLogger 带前缀的日志记录器
type PrefixLogger struct {
	prefix string
}

// NewPrefixLogger 创建带前缀的日志记录器
func NewPrefixLogger(prefix string) *PrefixLogger {
	return &PrefixLogger{prefix: prefix}
}

// Debug 调试日志
func (p *PrefixLogger) Debug(format string, v ...any) {
	Debug(p.prefix+format, v...)
}

// Info 信息日志
func (p *PrefixLogger) Info(format string, v ...any) {
	Info(p.prefix+format, v...)
}

// Warn 警告日志
func (p *PrefixLogger) Warn(format string, v ...any) {
	Warn(p.prefix+format, v...)
}

// Error 错误日志
func (p *PrefixLogger) Error(format string, v ...any) {
	Error(p.prefix+format, v...)
}




