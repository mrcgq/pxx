package argo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	plog "phantom-x/pkg/log"
)

const (
	cloudflaredReleaseURL = "https://github.com/cloudflare/cloudflared/releases/latest/download"
)

// FindCloudflared 查找 cloudflared 可执行文件
func FindCloudflared(customPath string) string {
	// 优先使用自定义路径
	if customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			return customPath
		}
	}

	// 检查 PATH
	if path, err := exec.LookPath("cloudflared"); err == nil {
		return path
	}

	// 检查常见位置
	commonPaths := []string{
		"/usr/local/bin/cloudflared",
		"/usr/bin/cloudflared",
		"/opt/cloudflared/cloudflared",
		filepath.Join(os.Getenv("HOME"), ".local/bin/cloudflared"),
		filepath.Join(os.Getenv("HOME"), "cloudflared"),
	}

	if runtime.GOOS == "windows" {
		commonPaths = append(commonPaths,
			filepath.Join(os.Getenv("PROGRAMFILES"), "cloudflared", "cloudflared.exe"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "cloudflared", "cloudflared.exe"),
		)
	}

	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// InstallCloudflared 自动下载安装 cloudflared
func InstallCloudflared(ctx context.Context) (string, error) {
	plog.Info("[Argo] 正在下载 cloudflared...")

	// 确定下载 URL
	var filename string
	switch runtime.GOOS {
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			filename = "cloudflared-linux-amd64"
		case "arm64":
			filename = "cloudflared-linux-arm64"
		case "arm":
			filename = "cloudflared-linux-arm"
		default:
			return "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
		}
	case "darwin":
		switch runtime.GOARCH {
		case "amd64":
			filename = "cloudflared-darwin-amd64.tgz"
		case "arm64":
			filename = "cloudflared-darwin-arm64.tgz"
		default:
			return "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
		}
	case "windows":
		switch runtime.GOARCH {
		case "amd64":
			filename = "cloudflared-windows-amd64.exe"
		case "arm64":
			filename = "cloudflared-windows-arm64.exe"
		default:
			return "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
		}
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	downloadURL := fmt.Sprintf("%s/%s", cloudflaredReleaseURL, filename)

	// 确定安装路径
	var installPath string
	if runtime.GOOS == "windows" {
		installPath = filepath.Join(os.Getenv("LOCALAPPDATA"), "cloudflared", "cloudflared.exe")
	} else {
		// 优先安装到用户目录
		homeDir := os.Getenv("HOME")
		localBin := filepath.Join(homeDir, ".local", "bin")
		if err := os.MkdirAll(localBin, 0755); err == nil {
			installPath = filepath.Join(localBin, "cloudflared")
		} else {
			// 回退到临时目录
			installPath = filepath.Join(os.TempDir(), "cloudflared")
		}
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(installPath), 0755); err != nil {
		return "", fmt.Errorf("create directory: %w", err)
	}

	// 下载文件
	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	// 写入文件
	out, err := os.OpenFile(installPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return "", fmt.Errorf("create file: %w", err)
	}
	defer out.Close()

	written, err := io.Copy(out, resp.Body)
	if err != nil {
		return "", fmt.Errorf("write file: %w", err)
	}

	plog.Info("[Argo] cloudflared 下载完成: %s (%.2f MB)", installPath, float64(written)/1024/1024)

	// 验证
	if err := exec.Command(installPath, "version").Run(); err != nil {
		return "", fmt.Errorf("verify cloudflared: %w", err)
	}

	return installPath, nil
}

// EnsureCloudflared 确保 cloudflared 可用
func EnsureCloudflared(ctx context.Context, customPath string, autoInstall bool) (string, error) {
	// 先查找
	path := FindCloudflared(customPath)
	if path != "" {
		plog.Debug("[Argo] 找到 cloudflared: %s", path)
		return path, nil
	}

	// 自动安装
	if autoInstall {
		return InstallCloudflared(ctx)
	}

	return "", fmt.Errorf("cloudflared not found, please install it or enable auto_install_cfd")
}
