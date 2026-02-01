#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#                     Phantom-X 一键安装脚本 v2.0
#                     高性能 · 抗探测 · 0-RTT 隧道代理
#═══════════════════════════════════════════════════════════════════════════════
#
# 使用方法:
#   curl -fsSL https://raw.githubusercontent.com/mrcgq/px/main/scripts/install.sh | bash -s server
#   curl -fsSL https://raw.githubusercontent.com/mrcgq/px/main/scripts/install.sh | bash -s client
#
# 支持的命令:
#   server    - 安装服务端
#   client    - 安装客户端
#   update    - 更新已安装的组件
#   uninstall - 卸载
#   status    - 查看状态
#   help      - 显示帮助
#
#═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ==================== 全局变量 ====================
readonly SCRIPT_VERSION="1.1"
readonly GITHUB_REPO="mrcgq/px"
readonly GITHUB_RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main"
readonly GITHUB_API_URL="https://api.github.com/repos/${GITHUB_REPO}"
readonly GITHUB_RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/download"

readonly INSTALL_DIR="/opt/phantom-x"
readonly CONFIG_DIR="/etc/phantom-x"
readonly LOG_DIR="/var/log/phantom-x"
readonly SERVICE_NAME="phantom-x"
readonly BINARY_NAME_SERVER="phantom-x-server"
readonly BINARY_NAME_CLIENT="phantom-x-client"

# 默认版本（当无法从 GitHub 获取时使用）
readonly DEFAULT_VERSION="2.0.0"

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color
readonly BOLD='\033[1m'

# 运行时变量
OS=""
ARCH=""
VERSION=""
INSTALL_MODE=""
FORCE_INSTALL=false
SKIP_SERVICE=false
CUSTOM_PORT=""
CUSTOM_TOKEN=""
CUSTOM_VERSION=""

# ==================== 工具函数 ====================

# 日志函数
log_info()  { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step()  { echo -e "${BLUE}[→]${NC} $1"; }
log_debug() { [[ "${DEBUG:-}" == "1" ]] && echo -e "${PURPLE}[D]${NC} $1" || true; }

# 致命错误
die() {
    log_error "$1"
    exit "${2:-1}"
}

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检查是否为 root
is_root() {
    [[ $EUID -eq 0 ]]
}

# 需要 root 权限
require_root() {
    if ! is_root; then
        die "请使用 root 权限运行此脚本，或使用 sudo"
    fi
}

# 确认操作
confirm() {
    local prompt="${1:-确认继续?}"
    local default="${2:-n}"
    
    if [[ "$default" == "y" ]]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi
    
    read -rp "$prompt" response
    response="${response:-$default}"
    
    [[ "$response" =~ ^[Yy]$ ]]
}

# 打印分隔线
print_separator() {
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

# ==================== Banner ====================

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
    ____  __                  __                        _  __
   / __ \/ /_  ____ _____  / /_____  ____ ___        | |/ /
  / /_/ / __ \/ __ `/ __ \/ __/ __ \/ __ `__ \  _____\   / 
 / ____/ / / / /_/ / / / / /_/ /_/ / / / / / / /_____/   |  
/_/   /_/ /_/\__,_/_/ /_/\__/\____/_/ /_/ /_/       /_/|_|  
                                                            
    高性能 · 抗探测 · 0-RTT 隧道代理  v2.0
EOF
    echo -e "${NC}"
}

print_mini_banner() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}           ${BOLD}Phantom-X Installer v${SCRIPT_VERSION}${NC}                       ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ==================== 系统检测 ====================

detect_os() {
    local uname_s
    uname_s=$(uname -s)
    
    case "$uname_s" in
        Linux)
            OS="linux"
            ;;
        Darwin)
            OS="darwin"
            ;;
        FreeBSD)
            OS="freebsd"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            OS="windows"
            ;;
        *)
            die "不支持的操作系统: $uname_s"
            ;;
    esac
    
    log_debug "检测到操作系统: $OS"
}

detect_arch() {
    local uname_m
    uname_m=$(uname -m)
    
    case "$uname_m" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l|armv7|armhf)
            ARCH="arm"
            ;;
        armv6l)
            ARCH="arm"
            log_warn "ARMv6 支持有限，可能存在兼容性问题"
            ;;
        i386|i486|i586|i686)
            ARCH="386"
            ;;
        s390x)
            ARCH="s390x"
            ;;
        ppc64le)
            ARCH="ppc64le"
            ;;
        mips64le)
            ARCH="mips64le"
            ;;
        mips64)
            ARCH="mips64"
            ;;
        mipsle)
            ARCH="mipsle"
            ;;
        mips)
            ARCH="mips"
            ;;
        riscv64)
            ARCH="riscv64"
            ;;
        *)
            die "不支持的 CPU 架构: $uname_m"
            ;;
    esac
    
    log_debug "检测到 CPU 架构: $ARCH"
}

detect_init_system() {
    if [[ -d /run/systemd/system ]]; then
        echo "systemd"
    elif [[ -f /etc/init.d/cron ]] && [[ ! -d /run/systemd/system ]]; then
        echo "sysvinit"
    elif command_exists rc-service; then
        echo "openrc"
    elif [[ "$OS" == "darwin" ]]; then
        echo "launchd"
    else
        echo "unknown"
    fi
}

detect_package_manager() {
    if command_exists apt-get; then
        echo "apt"
    elif command_exists dnf; then
        echo "dnf"
    elif command_exists yum; then
        echo "yum"
    elif command_exists pacman; then
        echo "pacman"
    elif command_exists apk; then
        echo "apk"
    elif command_exists zypper; then
        echo "zypper"
    elif command_exists brew; then
        echo "brew"
    else
        echo "unknown"
    fi
}

get_distro_info() {
    local distro="unknown"
    local version="unknown"
    
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        distro="${ID:-unknown}"
        version="${VERSION_ID:-unknown}"
    elif [[ -f /etc/redhat-release ]]; then
        distro="rhel"
        version=$(cat /etc/redhat-release | grep -oE '[0-9]+\.[0-9]+' | head -1)
    elif [[ "$OS" == "darwin" ]]; then
        distro="macos"
        version=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
    fi
    
    echo "${distro}:${version}"
}

# ==================== 依赖检查 ====================

check_dependencies() {
    local missing=()
    local required=("curl" "tar" "gzip")
    
    for cmd in "${required[@]}"; do
        if ! command_exists "$cmd"; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "缺少必要依赖: ${missing[*]}"
        log_step "正在尝试自动安装..."
        
        local pm
        pm=$(detect_package_manager)
        
        case "$pm" in
            apt)
                apt-get update -qq && apt-get install -y -qq "${missing[@]}"
                ;;
            dnf)
                dnf install -y -q "${missing[@]}"
                ;;
            yum)
                yum install -y -q "${missing[@]}"
                ;;
            pacman)
                pacman -Sy --noconfirm "${missing[@]}"
                ;;
            apk)
                apk add --no-cache "${missing[@]}"
                ;;
            zypper)
                zypper install -y "${missing[@]}"
                ;;
            brew)
                brew install "${missing[@]}"
                ;;
            *)
                die "无法自动安装依赖，请手动安装: ${missing[*]}"
                ;;
        esac
        
        # 重新检查
        for cmd in "${missing[@]}"; do
            if ! command_exists "$cmd"; then
                die "依赖安装失败: $cmd"
            fi
        done
        
        log_info "依赖安装完成"
    fi
}

check_optional_dependencies() {
    local optional=("openssl" "wget" "jq")
    local missing=()
    
    for cmd in "${optional[@]}"; do
        if ! command_exists "$cmd"; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_debug "可选依赖缺失: ${missing[*]}"
    fi
}

# ==================== 网络函数 ====================

# 带重试的下载
download_file() {
    local url="$1"
    local output="$2"
    local description="${3:-文件}"
    local max_retry="${4:-3}"
    local retry=0
    
    while [[ $retry -lt $max_retry ]]; do
        log_step "下载 $description (尝试 $((retry + 1))/$max_retry)"
        log_debug "下载 URL: $url"
        
        if curl -fSL --progress-bar \
            --connect-timeout 30 \
            --max-time 300 \
            --retry 2 \
            -o "$output" \
            "$url" 2>/dev/null; then
            
            # 验证文件
            if [[ -f "$output" ]] && [[ -s "$output" ]]; then
                log_info "下载成功: $description"
                return 0
            fi
        fi
        
        retry=$((retry + 1))
        if [[ $retry -lt $max_retry ]]; then
            log_warn "下载失败，${retry} 秒后重试..."
            sleep "$retry"
        fi
    done
    
    return 1
}

# 获取最新版本号 (改进版)
get_latest_version() {
    local version=""
    
    log_debug "正在获取最新版本..."
    
    # 方法1: 从 releases/latest API 获取
    log_debug "尝试方法1: releases/latest API"
    version=$(curl -sL --connect-timeout 10 --max-time 30 \
        -H "Accept: application/vnd.github.v3+json" \
        "${GITHUB_API_URL}/releases/latest" 2>/dev/null | \
        grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | \
        head -1 | \
        sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | \
        sed 's/^v//')
    
    if [[ -n "$version" ]] && [[ "$version" != "null" ]]; then
        log_debug "方法1成功: $version"
        echo "$version"
        return 0
    fi
    
    # 方法2: 从 releases 列表获取
    log_debug "尝试方法2: releases 列表"
    version=$(curl -sL --connect-timeout 10 --max-time 30 \
        -H "Accept: application/vnd.github.v3+json" \
        "${GITHUB_API_URL}/releases" 2>/dev/null | \
        grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | \
        head -1 | \
        sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | \
        sed 's/^v//')
    
    if [[ -n "$version" ]] && [[ "$version" != "null" ]]; then
        log_debug "方法2成功: $version"
        echo "$version"
        return 0
    fi
    
    # 方法3: 从 tags 获取
    log_debug "尝试方法3: tags API"
    version=$(curl -sL --connect-timeout 10 --max-time 30 \
        -H "Accept: application/vnd.github.v3+json" \
        "${GITHUB_API_URL}/tags" 2>/dev/null | \
        grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' | \
        head -1 | \
        sed 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | \
        sed 's/^v//')
    
    if [[ -n "$version" ]] && [[ "$version" != "null" ]]; then
        log_debug "方法3成功: $version"
        echo "$version"
        return 0
    fi
    
    # 方法4: 从 GitHub releases 页面 HTML 解析
    log_debug "尝试方法4: releases 页面解析"
    version=$(curl -sL --connect-timeout 10 --max-time 30 \
        "https://github.com/${GITHUB_REPO}/releases" 2>/dev/null | \
        grep -oE '/releases/tag/v?[0-9]+\.[0-9]+\.[0-9]+' | \
        head -1 | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    
    if [[ -n "$version" ]]; then
        log_debug "方法4成功: $version"
        echo "$version"
        return 0
    fi
    
    # 方法5: 使用 wget 作为备用
    if command_exists wget; then
        log_debug "尝试方法5: wget"
        version=$(wget -qO- --timeout=10 \
            "${GITHUB_API_URL}/releases/latest" 2>/dev/null | \
            grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | \
            head -1 | \
            sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | \
            sed 's/^v//')
        
        if [[ -n "$version" ]] && [[ "$version" != "null" ]]; then
            log_debug "方法5成功: $version"
            echo "$version"
            return 0
        fi
    fi
    
    log_debug "所有方法均失败"
    echo ""
    return 1
}

# 获取当前安装版本
get_installed_version() {
    local binary="$1"
    local version=""
    
    if [[ -f "$binary" ]] && [[ -x "$binary" ]]; then
        version=$("$binary" -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    fi
    
    echo "$version"
}

# 版本比较 (返回: 0=相等, 1=v1>v2, 2=v1<v2)
compare_versions() {
    local v1="$1"
    local v2="$2"
    
    if [[ "$v1" == "$v2" ]]; then
        echo 0
        return
    fi
    
    # 使用 sort -V 进行版本比较
    local higher
    higher=$(printf '%s\n%s' "$v1" "$v2" | sort -V | tail -1)
    
    if [[ "$higher" == "$v1" ]]; then
        echo 1
    else
        echo 2
    fi
}

# ==================== 证书生成 ====================

generate_self_signed_cert() {
    local cert_dir="$1"
    local domain="${2:-localhost}"
    local days="${3:-365}"
    
    if ! command_exists openssl; then
        log_warn "未安装 openssl，跳过证书生成"
        log_warn "请手动配置 TLS 证书"
        return 1
    fi
    
    log_step "生成自签名证书 (域名: $domain, 有效期: ${days}天)..."
    
    # 创建临时配置文件
    local config_file
    config_file=$(mktemp)
    
    cat > "$config_file" << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
C = US
ST = State
L = City
O = Phantom-X
OU = Tunnel Proxy
CN = $domain

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $domain
DNS.2 = localhost
DNS.3 = *.${domain}
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
    
    # 生成私钥和证书
    openssl req -x509 -nodes -days "$days" -newkey rsa:2048 \
        -keyout "${cert_dir}/key.pem" \
        -out "${cert_dir}/cert.pem" \
        -config "$config_file" \
        2>/dev/null
    
    # 清理临时文件
    rm -f "$config_file"
    
    # 设置权限
    chmod 600 "${cert_dir}/key.pem"
    chmod 644 "${cert_dir}/cert.pem"
    
    log_info "自签名证书已生成"
    log_warn "⚠️  生产环境请使用正式证书（如 Let's Encrypt）"
    
    return 0
}

# ==================== Token 生成 ====================

generate_token() {
    local length="${1:-32}"
    
    if command_exists openssl; then
        openssl rand -base64 48 | tr -d '/+=' | head -c "$length"
    elif [[ -f /dev/urandom ]]; then
        head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c "$length"
    else
        # 回退方案
        date +%s%N | sha256sum | head -c "$length"
    fi
}

# ==================== 服务管理 ====================

create_systemd_service() {
    local service_type="$1"  # server 或 client
    local binary_path="$2"
    local config_path="$3"
    
    local service_name="${SERVICE_NAME}-${service_type}"
    local service_file="/etc/systemd/system/${service_name}.service"
    local description="Phantom-X ${service_type^}"
    
    log_step "创建 systemd 服务: $service_name"
    
    cat > "$service_file" << EOF
[Unit]
Description=${description} - High Performance Tunnel Proxy
Documentation=https://github.com/${GITHUB_REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${binary_path} -c ${config_path}
Restart=always
RestartSec=3
StartLimitInterval=60
StartLimitBurst=5

# 资源限制
LimitNOFILE=1048576
LimitNPROC=512
LimitCORE=infinity

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${CONFIG_DIR} ${LOG_DIR}
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true

# 日志
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${service_name}

# 环境变量
Environment=GOMAXPROCS=0

[Install]
WantedBy=multi-user.target
EOF
    
    # 重载 systemd
    systemctl daemon-reload
    
    log_info "服务文件已创建: $service_file"
}

create_openrc_service() {
    local service_type="$1"
    local binary_path="$2"
    local config_path="$3"
    
    local service_name="${SERVICE_NAME}-${service_type}"
    local service_file="/etc/init.d/${service_name}"
    
    log_step "创建 OpenRC 服务: $service_name"
    
    cat > "$service_file" << EOF
#!/sbin/openrc-run

name="Phantom-X ${service_type^}"
description="High Performance Tunnel Proxy"

command="${binary_path}"
command_args="-c ${config_path}"
command_background=true
pidfile="/run/${service_name}.pid"
output_log="${LOG_DIR}/${service_name}.log"
error_log="${LOG_DIR}/${service_name}.err"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --mode 0755 ${LOG_DIR}
}
EOF
    
    chmod +x "$service_file"
    rc-update add "$service_name" default 2>/dev/null || true
    
    log_info "服务文件已创建: $service_file"
}

create_launchd_service() {
    local service_type="$1"
    local binary_path="$2"
    local config_path="$3"
    
    local service_name="com.phantomx.${service_type}"
    local plist_file="/Library/LaunchDaemons/${service_name}.plist"
    
    log_step "创建 launchd 服务: $service_name"
    
    cat > "$plist_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${service_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${binary_path}</string>
        <string>-c</string>
        <string>${config_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/${SERVICE_NAME}-${service_type}.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/${SERVICE_NAME}-${service_type}.err</string>
</dict>
</plist>
EOF
    
    log_info "服务文件已创建: $plist_file"
}

# 创建 logrotate 配置
create_logrotate_config() {
    local logrotate_file="/etc/logrotate.d/phantom-x"
    
    if [[ ! -d "/etc/logrotate.d" ]]; then
        log_debug "logrotate 未安装，跳过配置"
        return 0
    fi
    
    log_step "创建 logrotate 配置..."
    
    cat > "$logrotate_file" << EOF
${LOG_DIR}/*.log ${LOG_DIR}/*.err {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    sharedscripts
    postrotate
        systemctl reload ${SERVICE_NAME}-server >/dev/null 2>&1 || true
    endscript
}
EOF
    
    chmod 644 "$logrotate_file"
    log_info "logrotate 配置已创建: $logrotate_file"
}

# 优化内核参数（服务端）
optimize_sysctl() {
    if [[ "$OS" != "linux" ]]; then
        log_debug "非 Linux 系统，跳过内核参数优化"
        return 0
    fi
    
    local sysctl_file="/etc/sysctl.d/99-phantom-x.conf"
    
    log_step "优化内核参数..."
    
    cat > "$sysctl_file" << 'EOF'
# Phantom-X 网络性能优化

# UDP 缓冲区
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# TCP 缓冲区
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216

# 连接队列
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# TIME_WAIT 优化
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30

# 文件描述符
fs.file-max = 1048576
EOF
    
    chmod 644 "$sysctl_file"
    
    # 立即应用
    if command_exists sysctl; then
        sysctl -p "$sysctl_file" >/dev/null 2>&1 || true
    fi
    
    log_info "内核参数已优化: $sysctl_file"
}

# 启用服务
enable_service() {
    local service_type="$1"
    local init_system
    init_system=$(detect_init_system)
    
    case "$init_system" in
        systemd)
            systemctl enable "${SERVICE_NAME}-${service_type}" >/dev/null 2>&1 || true
            ;;
        openrc)
            rc-update add "${SERVICE_NAME}-${service_type}" default 2>/dev/null || true
            ;;
        launchd)
            launchctl load "/Library/LaunchDaemons/com.phantomx.${service_type}.plist" 2>/dev/null || true
            ;;
    esac
}

# 启动服务
start_service() {
    local service_type="$1"
    local init_system
    init_system=$(detect_init_system)
    
    case "$init_system" in
        systemd)
            systemctl start "${SERVICE_NAME}-${service_type}"
            ;;
        openrc)
            rc-service "${SERVICE_NAME}-${service_type}" start
            ;;
        launchd)
            launchctl start "com.phantomx.${service_type}"
            ;;
        *)
            log_warn "未知的 init 系统，请手动启动服务"
            return 1
            ;;
    esac
}

# 停止服务
stop_service() {
    local service_type="$1"
    local init_system
    init_system=$(detect_init_system)
    
    case "$init_system" in
        systemd)
            systemctl stop "${SERVICE_NAME}-${service_type}" 2>/dev/null || true
            ;;
        openrc)
            rc-service "${SERVICE_NAME}-${service_type}" stop 2>/dev/null || true
            ;;
        launchd)
            launchctl stop "com.phantomx.${service_type}" 2>/dev/null || true
            ;;
    esac
}

# 检查服务状态
is_service_running() {
    local service_type="$1"
    local init_system
    init_system=$(detect_init_system)
    
    case "$init_system" in
        systemd)
            systemctl is-active --quiet "${SERVICE_NAME}-${service_type}" 2>/dev/null
            ;;
        openrc)
            rc-service "${SERVICE_NAME}-${service_type}" status >/dev/null 2>&1
            ;;
        launchd)
            launchctl list "com.phantomx.${service_type}" >/dev/null 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

# ==================== 服务端安装 ====================

install_server() {
    print_mini_banner
    require_root
    check_dependencies
    detect_os
    detect_arch
    
    log_step "开始安装 Phantom-X 服务端..."
    echo ""
    
    # 获取版本
    if [[ -n "$CUSTOM_VERSION" ]]; then
        VERSION="$CUSTOM_VERSION"
        log_info "使用指定版本: v${VERSION}"
    else
        log_step "正在获取最新版本..."
        VERSION=$(get_latest_version)
        
        if [[ -z "$VERSION" ]]; then
            log_warn "无法从 GitHub 获取版本信息"
            log_warn "可能的原因: 网络问题、API 限制、仓库无 releases"
            echo ""
            
            # 询问是否使用默认版本
            if confirm "是否使用默认版本 v${DEFAULT_VERSION}?" "y"; then
                VERSION="$DEFAULT_VERSION"
            else
                # 让用户手动输入版本
                read -rp "请输入版本号 (如 2.0.0): " user_version
                if [[ -n "$user_version" ]]; then
                    VERSION="${user_version#v}"
                else
                    die "未指定版本，安装终止"
                fi
            fi
        fi
        
        log_info "目标版本: v${VERSION}"
    fi
    
    # 检查是否已安装
    local current_version
    current_version=$(get_installed_version "${INSTALL_DIR}/${BINARY_NAME_SERVER}")
    if [[ -n "$current_version" ]] && [[ "$FORCE_INSTALL" != "true" ]]; then
        log_warn "已安装版本: v${current_version}"
        if ! confirm "是否覆盖安装?"; then
            log_info "已取消安装"
            return 0
        fi
    fi
    
    # 创建目录
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 755 "$LOG_DIR"
    
    # 构建下载 URL
    local download_url="${GITHUB_RELEASE_URL}/v${VERSION}/${BINARY_NAME_SERVER}-${OS}-${ARCH}.tar.gz"
    local temp_dir
    temp_dir=$(mktemp -d)
    local archive_file="${temp_dir}/phantom-x-server.tar.gz"
    
    log_debug "下载 URL: $download_url"
    
    # 下载
    if ! download_file "$download_url" "$archive_file" "服务端二进制"; then
        rm -rf "$temp_dir"
        echo ""
        log_error "下载失败"
        log_warn "请检查以下内容:"
        echo "  1. 网络连接是否正常"
        echo "  2. 版本号 v${VERSION} 是否存在"
        echo "  3. 文件 ${BINARY_NAME_SERVER}-${OS}-${ARCH}.tar.gz 是否在 releases 中"
        echo ""
        echo "手动下载地址: $download_url"
        die "安装终止"
    fi
    
    # 解压
    log_step "解压安装文件..."
    if ! tar -xzf "$archive_file" -C "$temp_dir" 2>/dev/null; then
        rm -rf "$temp_dir"
        die "解压失败，文件可能已损坏"
    fi
    
    # 列出解压后的文件（调试用）
    log_debug "解压后文件: $(ls -la "$temp_dir")"
    
    # 查找并安装二进制
    local binary_found=false
    for name in "${BINARY_NAME_SERVER}" "${BINARY_NAME_SERVER}-${OS}-${ARCH}" "phantom-x-server" "server"; do
        if [[ -f "${temp_dir}/${name}" ]]; then
            # 停止现有服务
            stop_service "server" 2>/dev/null || true
            
            mv "${temp_dir}/${name}" "${INSTALL_DIR}/${BINARY_NAME_SERVER}"
            binary_found=true
            log_debug "找到二进制文件: ${name}"
            break
        fi
    done
    
    if [[ "$binary_found" != "true" ]]; then
        log_error "未找到可执行文件，解压目录内容:"
        ls -la "$temp_dir"
        rm -rf "$temp_dir"
        die "安装失败"
    fi
    
    # 设置权限
    chmod +x "${INSTALL_DIR}/${BINARY_NAME_SERVER}"
    
    # 创建软链接
    ln -sf "${INSTALL_DIR}/${BINARY_NAME_SERVER}" /usr/local/bin/phantom-x-server
    
    # 清理临时文件
    rm -rf "$temp_dir"
    
    # 创建配置文件
    if [[ ! -f "${CONFIG_DIR}/server.yaml" ]] || [[ "$FORCE_INSTALL" == "true" ]]; then
        create_server_config
    else
        log_info "配置文件已存在，跳过创建"
    fi
    
    # 生成证书（如果不存在）
    if [[ ! -f "${CONFIG_DIR}/cert.pem" ]] || [[ ! -f "${CONFIG_DIR}/key.pem" ]]; then
        generate_self_signed_cert "$CONFIG_DIR" || true
    fi
    
    # 创建服务
    if [[ "$SKIP_SERVICE" != "true" ]]; then
        local init_system
        init_system=$(detect_init_system)
        
        case "$init_system" in
            systemd)
                create_systemd_service "server" "${INSTALL_DIR}/${BINARY_NAME_SERVER}" "${CONFIG_DIR}/server.yaml"
                enable_service "server"
                ;;
            openrc)
                create_openrc_service "server" "${INSTALL_DIR}/${BINARY_NAME_SERVER}" "${CONFIG_DIR}/server.yaml"
                ;;
            launchd)
                create_launchd_service "server" "${INSTALL_DIR}/${BINARY_NAME_SERVER}" "${CONFIG_DIR}/server.yaml"
                ;;
            *)
                log_warn "未知的 init 系统，跳过服务创建"
                ;;
        esac
    fi
    
    # 创建 logrotate 配置
    create_logrotate_config
    
    # 优化内核参数
    optimize_sysctl
    
    # 完成
    print_server_success
}

create_server_config() {
    local token
    token="${CUSTOM_TOKEN:-$(generate_token)}"
    local port="${CUSTOM_PORT:-443}"
    
    cat > "${CONFIG_DIR}/server.yaml" << EOF
# ═══════════════════════════════════════════════════════════════
# Phantom-X 服务端配置
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 版本: v${VERSION}
# ═══════════════════════════════════════════════════════════════

# 监听地址
listen: ":${port}"

# TLS 证书路径
cert: "${CONFIG_DIR}/cert.pem"
key: "${CONFIG_DIR}/key.pem"

# 认证令牌（请妥善保管！）
token: "${token}"

# WebSocket 路径（建议修改以提高隐蔽性）
ws_path: "/ws"

# ═══════════════════════════════════════════════════════════════
# 性能调优
# ═══════════════════════════════════════════════════════════════

# 每个连接的最大流数量
max_streams_per_conn: 1000

# 超时设置
read_timeout: 60s
write_timeout: 10s
idle_timeout: 120s

# ═══════════════════════════════════════════════════════════════
# 日志设置
# ═══════════════════════════════════════════════════════════════

# 日志级别: debug, info, warn, error
log_level: "info"
EOF
    
    chmod 600 "${CONFIG_DIR}/server.yaml"
    
    log_info "配置文件已创建: ${CONFIG_DIR}/server.yaml"
    
    echo ""
    print_separator
    echo -e "${YELLOW}  🔑 认证令牌: ${WHITE}${token}${NC}"
    echo -e "${YELLOW}  请妥善保管此令牌，客户端连接时需要使用！${NC}"
    print_separator
    echo ""
}

print_server_success() {
    echo ""
    print_separator
    echo -e "${GREEN}${BOLD}  ✅ 服务端安装完成！${NC}"
    print_separator
    echo ""
    echo -e "${CYAN}下一步操作:${NC}"
    echo ""
    echo -e "  ${WHITE}1.${NC} 配置 TLS 证书（推荐使用 Let's Encrypt）:"
    echo -e "     ${BLUE}# 安装 certbot${NC}"
    echo "     apt install certbot  # Debian/Ubuntu"
    echo "     yum install certbot  # CentOS/RHEL"
    echo ""
    echo -e "     ${BLUE}# 申请证书${NC}"
    echo "     certbot certonly --standalone -d your-domain.com"
    echo ""
    echo -e "     ${BLUE}# 复制证书${NC}"
    echo "     cp /etc/letsencrypt/live/your-domain.com/fullchain.pem ${CONFIG_DIR}/cert.pem"
    echo "     cp /etc/letsencrypt/live/your-domain.com/privkey.pem ${CONFIG_DIR}/key.pem"
    echo ""
    echo -e "  ${WHITE}2.${NC} 编辑配置文件:"
    echo "     nano ${CONFIG_DIR}/server.yaml"
    echo ""
    echo -e "  ${WHITE}3.${NC} 启动服务:"
    echo "     systemctl start ${SERVICE_NAME}-server"
    echo ""
    echo -e "  ${WHITE}4.${NC} 查看状态:"
    echo "     systemctl status ${SERVICE_NAME}-server"
    echo ""
    echo -e "  ${WHITE}5.${NC} 查看日志:"
    echo "     journalctl -u ${SERVICE_NAME}-server -f"
    echo ""
    print_separator
}

# ==================== 客户端安装 ====================

install_client() {
    print_mini_banner
    check_dependencies
    detect_os
    detect_arch
    
    log_step "开始安装 Phantom-X 客户端..."
    echo ""
    
    # 获取版本
    if [[ -n "$CUSTOM_VERSION" ]]; then
        VERSION="$CUSTOM_VERSION"
        log_info "使用指定版本: v${VERSION}"
    else
        log_step "正在获取最新版本..."
        VERSION=$(get_latest_version)
        
        if [[ -z "$VERSION" ]]; then
            log_warn "无法从 GitHub 获取版本信息"
            
            if confirm "是否使用默认版本 v${DEFAULT_VERSION}?" "y"; then
                VERSION="$DEFAULT_VERSION"
            else
                read -rp "请输入版本号 (如 2.0.0): " user_version
                if [[ -n "$user_version" ]]; then
                    VERSION="${user_version#v}"
                else
                    die "未指定版本，安装终止"
                fi
            fi
        fi
        
        log_info "目标版本: v${VERSION}"
    fi
    
    # 确定安装路径
    local install_path="/usr/local/bin/phantom-x"
    local config_dir="${HOME}/.config/phantom-x"
    local need_sudo=false
    
    # 检查是否需要 sudo
    if [[ ! -w "$(dirname "$install_path")" ]]; then
        if ! is_root; then
            need_sudo=true
            log_warn "需要 sudo 权限安装到 /usr/local/bin"
        fi
    fi
    
    # 创建临时目录
    local temp_dir
    temp_dir=$(mktemp -d)
    
    # 构建下载 URL
    local download_url="${GITHUB_RELEASE_URL}/v${VERSION}/${BINARY_NAME_CLIENT}-${OS}-${ARCH}.tar.gz"
    local archive_file="${temp_dir}/phantom-x-client.tar.gz"
    
    log_debug "下载 URL: $download_url"
    
    # 下载
    if ! download_file "$download_url" "$archive_file" "客户端二进制"; then
        rm -rf "$temp_dir"
        die "下载失败，请检查网络或版本号"
    fi
    
    # 解压
    log_step "解压安装文件..."
    if ! tar -xzf "$archive_file" -C "$temp_dir" 2>/dev/null; then
        rm -rf "$temp_dir"
        die "解压失败，文件可能已损坏"
    fi
    
    # 查找可执行文件
    local binary_path=""
    for name in "${BINARY_NAME_CLIENT}" "${BINARY_NAME_CLIENT}-${OS}-${ARCH}" "phantom-x-client" "client" "phantom-x"; do
        if [[ -f "${temp_dir}/${name}" ]]; then
            binary_path="${temp_dir}/${name}"
            log_debug "找到二进制文件: ${name}"
            break
        fi
    done
    
    if [[ -z "$binary_path" ]]; then
        log_error "未找到可执行文件，解压目录内容:"
        ls -la "$temp_dir"
        rm -rf "$temp_dir"
        die "安装失败"
    fi
    
    # 安装
    log_step "安装到 ${install_path}..."
    if [[ "$need_sudo" == "true" ]]; then
        sudo mv "$binary_path" "$install_path"
        sudo chmod +x "$install_path"
    else
        mv "$binary_path" "$install_path"
        chmod +x "$install_path"
    fi
    
    # 创建用户配置目录
    mkdir -p "$config_dir"
    
    # 创建示例配置
    if [[ ! -f "${config_dir}/client.yaml" ]]; then
        create_client_config "$config_dir"
    fi
    
    # 清理
    rm -rf "$temp_dir"
    
    # 完成
    print_client_success "$config_dir"
}

create_client_config() {
    local config_dir="$1"
    
    cat > "${config_dir}/client.yaml" << 'EOF'
# ═══════════════════════════════════════════════════════════════
# Phantom-X 客户端配置
# ═══════════════════════════════════════════════════════════════

# 服务器地址 (必填)
server: "wss://your-server.com:443/ws"

# 认证令牌 (必填)
token: "your-token-here"

# 客户端 ID (留空自动生成)
client_id: ""

# ═══════════════════════════════════════════════════════════════
# SOCKS5 代理设置
# ═══════════════════════════════════════════════════════════════

# SOCKS5 监听地址
socks5_listen: ":1080"

# SOCKS5 认证 (格式: user:pass，留空不验证)
socks5_auth: ""

# ═══════════════════════════════════════════════════════════════
# 连接设置
# ═══════════════════════════════════════════════════════════════

# 连接池大小 (1-10)
num_connections: 3

# 超时设置
write_timeout: 10s
read_timeout: 60s

# ═══════════════════════════════════════════════════════════════
# TLS 设置
# ═══════════════════════════════════════════════════════════════

# 跳过证书验证 (仅测试用)
insecure: false

# ═══════════════════════════════════════════════════════════════
# ECH (加密客户端握手) - 增强隐私保护
# ═══════════════════════════════════════════════════════════════
enable_ech: true
ech_domain: "cloudflare-ech.com"
ech_dns: "https://doh.pub/dns-query"

# ═══════════════════════════════════════════════════════════════
# 流量混淆 - 抗流量分析
# ═══════════════════════════════════════════════════════════════
enable_padding: true
padding_min_size: 64
padding_max_size: 256
padding_distribution: "mimicry"  # uniform, normal, mimicry

# ═══════════════════════════════════════════════════════════════
# IP 策略
# ═══════════════════════════════════════════════════════════════
# 可选值: "", "4", "6", "4,6", "6,4"
ip_strategy: ""

# ═══════════════════════════════════════════════════════════════
# 日志设置
# ═══════════════════════════════════════════════════════════════
log_level: "info"
EOF
    
    log_info "示例配置已创建: ${config_dir}/client.yaml"
}

print_client_success() {
    local config_dir="$1"
    
    echo ""
    print_separator
    echo -e "${GREEN}${BOLD}  ✅ 客户端安装完成！${NC}"
    print_separator
    echo ""
    echo -e "${CYAN}使用方法:${NC}"
    echo ""
    echo -e "  ${WHITE}命令行模式:${NC}"
    echo "    phantom-x -s wss://server:443/ws -token your-token"
    echo ""
    echo -e "  ${WHITE}配置文件模式:${NC}"
    echo "    # 编辑配置文件"
    echo "    nano ${config_dir}/client.yaml"
    echo ""
    echo "    # 使用配置文件启动"
    echo "    phantom-x -c ${config_dir}/client.yaml"
    echo ""
    echo -e "${CYAN}常用选项:${NC}"
    echo "    -s        服务器地址 (wss://host:port/path)"
    echo "    -token    认证令牌"
    echo "    -l        SOCKS5 监听地址 (默认 :1080)"
    echo "    -insecure 跳过证书验证"
    echo "    -no-ech   禁用 ECH"
    echo "    -stats    退出时显示统计"
    echo "    -v        显示版本"
    echo ""
    print_separator
}

# ==================== 更新 ====================

do_update() {
    print_mini_banner
    require_root
    check_dependencies
    detect_os
    detect_arch
    
    log_step "检查更新..."
    
    # 检查已安装的组件
    local server_installed=false
    local client_installed=false
    local server_version=""
    local client_version=""
    
    if [[ -f "${INSTALL_DIR}/${BINARY_NAME_SERVER}" ]]; then
        server_installed=true
        server_version=$(get_installed_version "${INSTALL_DIR}/${BINARY_NAME_SERVER}")
    fi
    
    if command_exists phantom-x; then
        client_installed=true
        client_version=$(get_installed_version "$(command -v phantom-x)")
    fi
    
    if [[ "$server_installed" != "true" ]] && [[ "$client_installed" != "true" ]]; then
        die "未检测到已安装的 Phantom-X 组件"
    fi
    
    # 获取最新版本
    if [[ -n "$CUSTOM_VERSION" ]]; then
        VERSION="$CUSTOM_VERSION"
    else
        VERSION=$(get_latest_version)
        if [[ -z "$VERSION" ]]; then
            log_warn "无法从 GitHub 获取最新版本"
            read -rp "请输入目标版本号 (如 2.0.0): " user_version
            if [[ -n "$user_version" ]]; then
                VERSION="${user_version#v}"
            else
                die "未指定版本，更新终止"
            fi
        fi
    fi
    
    echo ""
    echo -e "${CYAN}版本信息:${NC}"
    echo "  最新版本: v${VERSION}"
    
    local need_update=false
    
    if [[ "$server_installed" == "true" ]]; then
        echo "  服务端当前: v${server_version:-未知}"
        if [[ "$server_version" != "$VERSION" ]]; then
            need_update=true
        fi
    fi
    
    if [[ "$client_installed" == "true" ]]; then
        echo "  客户端当前: v${client_version:-未知}"
        if [[ "$client_version" != "$VERSION" ]]; then
            need_update=true
        fi
    fi
    
    echo ""
    
    if [[ "$need_update" != "true" ]]; then
        log_info "已是最新版本，无需更新"
        return 0
    fi
    
    if ! confirm "是否更新到 v${VERSION}?"; then
        log_info "已取消更新"
        return 0
    fi
    
    # 备份配置
    if [[ -f "${CONFIG_DIR}/server.yaml" ]]; then
        log_step "备份配置文件..."
        cp "${CONFIG_DIR}/server.yaml" "${CONFIG_DIR}/server.yaml.bak.$(date +%Y%m%d%H%M%S)"
        log_info "配置已备份"
    fi
    
    # 更新服务端
    if [[ "$server_installed" == "true" ]] && [[ "$server_version" != "$VERSION" ]]; then
        log_step "更新服务端..."
        
        # 停止服务
        stop_service "server" 2>/dev/null || true
        
        # 下载新版本
        local temp_dir
        temp_dir=$(mktemp -d)
        local download_url="${GITHUB_RELEASE_URL}/v${VERSION}/${BINARY_NAME_SERVER}-${OS}-${ARCH}.tar.gz"
        local archive_file="${temp_dir}/phantom-x-server.tar.gz"
        
        if download_file "$download_url" "$archive_file" "服务端"; then
            tar -xzf "$archive_file" -C "$temp_dir" 2>/dev/null
            
            for name in "${BINARY_NAME_SERVER}" "${BINARY_NAME_SERVER}-${OS}-${ARCH}" "phantom-x-server" "server"; do
                if [[ -f "${temp_dir}/${name}" ]]; then
                    mv "${temp_dir}/${name}" "${INSTALL_DIR}/${BINARY_NAME_SERVER}"
                    chmod +x "${INSTALL_DIR}/${BINARY_NAME_SERVER}"
                    break
                fi
            done
            
            log_info "服务端更新完成"
            
            # 启动服务
            start_service "server" 2>/dev/null || true
        else
            log_error "服务端更新失败"
        fi
        
        rm -rf "$temp_dir"
    fi
    
    # 更新客户端
    if [[ "$client_installed" == "true" ]] && [[ "$client_version" != "$VERSION" ]]; then
        log_step "更新客户端..."
        
        local temp_dir
        temp_dir=$(mktemp -d)
        local download_url="${GITHUB_RELEASE_URL}/v${VERSION}/${BINARY_NAME_CLIENT}-${OS}-${ARCH}.tar.gz"
        local archive_file="${temp_dir}/phantom-x-client.tar.gz"
        
        if download_file "$download_url" "$archive_file" "客户端"; then
            tar -xzf "$archive_file" -C "$temp_dir" 2>/dev/null
            
            local install_path
            install_path=$(command -v phantom-x)
            
            for name in "${BINARY_NAME_CLIENT}" "${BINARY_NAME_CLIENT}-${OS}-${ARCH}" "phantom-x-client" "client" "phantom-x"; do
                if [[ -f "${temp_dir}/${name}" ]]; then
                    mv "${temp_dir}/${name}" "$install_path"
                    chmod +x "$install_path"
                    break
                fi
            done
            
            log_info "客户端更新完成"
        else
            log_error "客户端更新失败"
        fi
        
        rm -rf "$temp_dir"
    fi
    
    echo ""
    log_info "更新完成！"
}

# ==================== 卸载 ====================

do_uninstall() {
    print_mini_banner
    require_root
    
    log_step "开始卸载 Phantom-X..."
    echo ""
    
    local init_system
    init_system=$(detect_init_system)
    
    # 停止并禁用服务端服务
    if is_service_running "server" 2>/dev/null; then
        log_step "停止服务端服务..."
        stop_service "server"
    fi
    
    case "$init_system" in
        systemd)
            if [[ -f "/etc/systemd/system/${SERVICE_NAME}-server.service" ]]; then
                systemctl disable "${SERVICE_NAME}-server" >/dev/null 2>&1 || true
                rm -f "/etc/systemd/system/${SERVICE_NAME}-server.service"
                systemctl daemon-reload
                log_info "已删除服务端 systemd 服务"
            fi
            ;;
        openrc)
            if [[ -f "/etc/init.d/${SERVICE_NAME}-server" ]]; then
                rc-update del "${SERVICE_NAME}-server" default 2>/dev/null || true
                rm -f "/etc/init.d/${SERVICE_NAME}-server"
                log_info "已删除服务端 OpenRC 服务"
            fi
            ;;
        launchd)
            if [[ -f "/Library/LaunchDaemons/com.phantomx.server.plist" ]]; then
                launchctl unload "/Library/LaunchDaemons/com.phantomx.server.plist" 2>/dev/null || true
                rm -f "/Library/LaunchDaemons/com.phantomx.server.plist"
                log_info "已删除服务端 launchd 服务"
            fi
            ;;
    esac
    
    # 删除程序文件
    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
        log_info "已删除程序目录: ${INSTALL_DIR}"
    fi
    
    # 删除软链接
    rm -f /usr/local/bin/phantom-x-server 2>/dev/null || true
    rm -f /usr/local/bin/phantom-x 2>/dev/null || true
    
    # 删除日志目录
    if [[ -d "$LOG_DIR" ]]; then
        rm -rf "$LOG_DIR"
        log_info "已删除日志目录: ${LOG_DIR}"
    fi
    
    # 删除 logrotate 配置
    if [[ -f "/etc/logrotate.d/phantom-x" ]]; then
        rm -f "/etc/logrotate.d/phantom-x"
        log_info "已删除 logrotate 配置"
    fi
    
    # 删除 sysctl 配置
    if [[ -f "/etc/sysctl.d/99-phantom-x.conf" ]]; then
        rm -f "/etc/sysctl.d/99-phantom-x.conf"
        sysctl --system >/dev/null 2>&1 || true
        log_info "已删除内核参数配置"
    fi
    
    # 询问是否删除配置    
    echo ""
    if [[ -d "$CONFIG_DIR" ]]; then
        if confirm "是否删除配置文件目录 ${CONFIG_DIR}?"; then
            rm -rf "$CONFIG_DIR"
            log_info "已删除配置目录"
        else
            log_info "配置目录已保留: ${CONFIG_DIR}"
        fi
    fi
    
    echo ""
    log_info "卸载完成！"
}

# ==================== 状态查看 ====================

show_status() {
    print_mini_banner
    
    detect_os
    detect_arch
    
    local distro_info
    distro_info=$(get_distro_info)
    local init_system
    init_system=$(detect_init_system)
    
    print_separator
    echo -e "${CYAN}${BOLD}  系统信息${NC}"
    print_separator
    echo "  操作系统: $(uname -s) $(uname -r)"
    echo "  发行版: ${distro_info}"
    echo "  架构: $ARCH"
    echo "  Init 系统: $init_system"
    echo ""
    
    print_separator
    echo -e "${CYAN}${BOLD}  服务端状态${NC}"
    print_separator
    
    if [[ -f "${INSTALL_DIR}/${BINARY_NAME_SERVER}" ]]; then
        local version
        version=$(get_installed_version "${INSTALL_DIR}/${BINARY_NAME_SERVER}")
        echo -e "  安装状态: ${GREEN}已安装${NC}"
        echo "  版本: v${version:-未知}"
        echo "  路径: ${INSTALL_DIR}/${BINARY_NAME_SERVER}"
        
        if is_service_running "server" 2>/dev/null; then
            echo -e "  服务状态: ${GREEN}运行中${NC}"
            
            # 获取进程信息 (仅 systemd)
            if [[ "$init_system" == "systemd" ]]; then
                local pid
                pid=$(systemctl show -p MainPID "${SERVICE_NAME}-server" 2>/dev/null | cut -d= -f2)
                if [[ -n "$pid" ]] && [[ "$pid" != "0" ]]; then
                    echo "  进程 PID: ${pid}"
                    
                    # 获取内存使用
                    local mem
                    mem=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
                    echo "  内存使用: ${mem}"
                    
                    # 获取运行时间
                    local uptime
                    uptime=$(systemctl show -p ActiveEnterTimestamp "${SERVICE_NAME}-server" 2>/dev/null | cut -d= -f2)
                    if [[ -n "$uptime" ]]; then
                        echo "  启动时间: ${uptime}"
                    fi
                fi
            fi
        else
            echo -e "  服务状态: ${YELLOW}已停止${NC}"
        fi
    else
        echo -e "  安装状态: ${RED}未安装${NC}"
    fi
    echo ""
    
    print_separator
    echo -e "${CYAN}${BOLD}  客户端状态${NC}"
    print_separator
    
    if command_exists phantom-x; then
        local version
        version=$(get_installed_version "$(command -v phantom-x)")
        echo -e "  安装状态: ${GREEN}已安装${NC}"
        echo "  版本: v${version:-未知}"
        echo "  路径: $(command -v phantom-x)"
    else
        echo -e "  安装状态: ${RED}未安装${NC}"
    fi
    echo ""
    
    print_separator
    echo -e "${CYAN}${BOLD}  配置信息${NC}"
    print_separator
    
    if [[ -f "${CONFIG_DIR}/server.yaml" ]]; then
        echo "  服务端配置: ${CONFIG_DIR}/server.yaml"
        
        # 提取配置信息
        local listen ws_path
        listen=$(grep -E '^\s*listen:' "${CONFIG_DIR}/server.yaml" 2>/dev/null | awk '{print $2}' | tr -d '"')
        ws_path=$(grep -E '^\s*ws_path:' "${CONFIG_DIR}/server.yaml" 2>/dev/null | awk '{print $2}' | tr -d '"')
        echo "    监听地址: ${listen:-未配置}"
        echo "    WebSocket路径: ${ws_path:-未配置}"
    fi
    
    if [[ -f "${HOME}/.config/phantom-x/client.yaml" ]]; then
        echo "  客户端配置: ${HOME}/.config/phantom-x/client.yaml"
    fi
    echo ""
    
    # 证书状态
    if [[ -f "${CONFIG_DIR}/cert.pem" ]]; then
        print_separator
        echo -e "${CYAN}${BOLD}  证书信息${NC}"
        print_separator
        
        if command_exists openssl; then
            local cert_info
            cert_info=$(openssl x509 -in "${CONFIG_DIR}/cert.pem" -noout -dates 2>/dev/null)
            local not_after
            not_after=$(echo "$cert_info" | grep 'notAfter' | cut -d= -f2)
            echo "  证书路径: ${CONFIG_DIR}/cert.pem"
            echo "  过期时间: ${not_after:-未知}"
            
            # 检查是否快过期
            local days_left
            days_left=$(openssl x509 -in "${CONFIG_DIR}/cert.pem" -noout -checkend 2592000 2>/dev/null && echo "30+" || echo "<30")
            if [[ "$days_left" == "<30" ]]; then
                echo -e "  状态: ${YELLOW}即将过期，请及时更新${NC}"
            else
                echo -e "  状态: ${GREEN}有效${NC}"
            fi
        fi
        echo ""
    fi
}

# ==================== 帮助信息 ====================

show_help() {
    print_banner
    
    cat << EOF

${GREEN}用法:${NC}
  $0 [命令] [选项]

${GREEN}命令:${NC}
  server      安装服务端
  client      安装客户端
  update      检查并更新
  uninstall   卸载 Phantom-X
  status      查看安装状态
  help        显示此帮助

${GREEN}选项:${NC}
  --force          强制覆盖安装
  --skip-service   跳过服务创建
  --port PORT      指定服务端口 (仅服务端)
  --token TOKEN    指定认证令牌 (仅服务端)
  --version VER    指定安装版本 (如 2.0.0)

${GREEN}示例:${NC}
  # 安装服务端
  $0 server

  # 安装客户端
  $0 client

  # 强制重新安装服务端
  $0 server --force

  # 指定端口和令牌
  $0 server --port 8443 --token mytoken123

  # 安装指定版本
  $0 server --version 2.0.0

  # 查看状态
  $0 status

  # 更新
  $0 update

${GREEN}快速安装:${NC}
  # 一键安装服务端
  curl -fsSL ${GITHUB_RAW_URL}/scripts/install.sh | bash -s server

  # 一键安装客户端
  curl -fsSL ${GITHUB_RAW_URL}/scripts/install.sh | bash -s client

${GREEN}环境变量:${NC}
  DEBUG=1           启用调试输出

${GREEN}项目地址:${NC}
  https://github.com/${GITHUB_REPO}

${GREEN}问题反馈:${NC}
  https://github.com/${GITHUB_REPO}/issues

EOF
}

# ==================== 参数解析 ====================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            server|client|update|uninstall|status|help)
                INSTALL_MODE="$1"
                shift
                ;;
            --force|-f)
                FORCE_INSTALL=true
                shift
                ;;
            --skip-service)
                SKIP_SERVICE=true
                shift
                ;;
            --port)
                CUSTOM_PORT="$2"
                shift 2
                ;;
            --token)
                CUSTOM_TOKEN="$2"
                shift 2
                ;;
            --version)
                CUSTOM_VERSION="${2#v}"
                shift 2
                ;;
            --debug)
                export DEBUG=1
                shift
                ;;
            -h|--help)
                INSTALL_MODE="help"
                shift
                ;;
            -v)
                echo "Phantom-X Installer v${SCRIPT_VERSION}"
                exit 0
                ;;
            *)
                die "未知参数: $1\n使用 '$0 help' 查看帮助"
                ;;
        esac
    done
}

# ==================== 主入口 ====================

main() {
    # 解析参数
    parse_args "$@"
    
    # 如果没有指定命令，显示帮助
    if [[ -z "$INSTALL_MODE" ]]; then
        show_help
        exit 0
    fi
    
    # 执行对应命令
    case "$INSTALL_MODE" in
        server)
            install_server
            ;;
        client)
            install_client
            ;;
        update|upgrade)
            do_update
            ;;
        uninstall|remove)
            do_uninstall
            ;;
        status)
            show_status
            ;;
        help)
            show_help
            ;;
        *)
            die "未知命令: $INSTALL_MODE"
            ;;
    esac
}

# 运行主程序
main "$@"
