#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#                     Phantom-X 交互式安装脚本 v3.0
#         支持 Cloudflare Tunnel · IP 优选 · 自动化部署
#═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

# ==================== 全局变量 ====================
readonly SCRIPT_VERSION="3.0.0"
readonly INSTALL_DIR="/opt/phantom-x"
readonly CONFIG_DIR="/etc/phantom-x"
readonly LOG_DIR="/var/log/phantom-x"
readonly SERVICE_NAME="phantom-x-server"
readonly BINARY_NAME="phantom-x-server"
readonly SYSTEMD_SERVICE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly CLOUDFLARED_SERVICE="/etc/systemd/system/cloudflared-phantom-x.service"

# GitHub 仓库
readonly GITHUB_REPO="mrcgq/pxx"
readonly GITHUB_API_URL="https://api.github.com/repos/${GITHUB_REPO}"
readonly GITHUB_RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/download"
readonly CLOUDFLARED_RELEASE="https://github.com/cloudflare/cloudflared/releases/latest/download"

# 颜色
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# 运行时变量
CURRENT_TOKEN=""
CURRENT_DOMAIN=""
CURRENT_PORT="443"
ARGO_DOMAIN=""
ARGO_ENABLED=false
CLOUDFLARED_PATH=""

# ==================== 工具函数 ====================

log_info()  { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step()  { echo -e "${BLUE}[→]${NC} $1"; }

die() { log_error "$1"; exit "${2:-1}"; }
command_exists() { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ $EUID -eq 0 ]]; }
require_root() { is_root || die "请使用 root 权限运行"; }

pause() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    read -rp "按 Enter 继续..."
    echo ""
}

confirm() {
    local prompt="${1:-确认继续?}"
    read -rp "$prompt [y/N]: " response
    [[ "$response" =~ ^[Yy]$ ]]
}

generate_token() {
    if command_exists openssl; then
        openssl rand -base64 32 | tr -d '/+=' | head -c 32
    else
        date +%s%N | sha256sum | head -c 32
    fi
}

# ==================== Banner ====================

print_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║   ____  __                  __                        _  __  ║
║  / __ \/ /_  ____ _____  / /_____  ____ ___        | |/ /  ║
║ / /_/ / __ \/ __ `/ __ \/ __/ __ \/ __ `__ \  ____ \   /   ║
║/ ____/ / / / /_/ / / / / /_/ /_/ / / / / / / /_____/   |    ║
║_/   /_/ /_/\__,_/_/ /_/\__/\____/_/ /_/ /_/       /_/|_|    ║
║                                                              ║
║         Cloudflare Tunnel · IP 优选 · 高性能代理 v3.0        ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# ==================== 状态检查 ====================

load_current_config() {
    if [[ -f "${CONFIG_DIR}/server.yaml" ]]; then
        CURRENT_TOKEN=$(grep "^token:" "${CONFIG_DIR}/server.yaml" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo "")
        CURRENT_PORT=$(grep "^listen:" "${CONFIG_DIR}/server.yaml" 2>/dev/null | awk -F: '{print $NF}' | tr -d '" ' || echo "443")
    fi
    
    if [[ -f "${CONFIG_DIR}/domain.txt" ]]; then
        CURRENT_DOMAIN=$(cat "${CONFIG_DIR}/domain.txt")
    fi
    
    if [[ -f "${CONFIG_DIR}/argo_domain.txt" ]]; then
        ARGO_DOMAIN=$(cat "${CONFIG_DIR}/argo_domain.txt")
        ARGO_ENABLED=true
    fi
    
    # 查找 cloudflared
    CLOUDFLARED_PATH=$(command -v cloudflared 2>/dev/null || echo "")
    if [[ -z "$CLOUDFLARED_PATH" ]] && [[ -f "/usr/local/bin/cloudflared" ]]; then
        CLOUDFLARED_PATH="/usr/local/bin/cloudflared"
    fi
}

check_installation_status() {
    local status=""
    
    if [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        status="${GREEN}已安装${NC}"
        
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            status="${status} | ${GREEN}运行中${NC}"
        else
            status="${status} | ${YELLOW}已停止${NC}"
        fi
    else
        status="${RED}未安装${NC}"
    fi
    
    echo -e "  服务状态: $status"
    
    if [[ "$ARGO_ENABLED" == true ]] && systemctl is-active --quiet "cloudflared-phantom-x" 2>/dev/null; then
        echo -e "  Argo隧道: ${GREEN}已启用${NC} | 域名: ${GREEN}${ARGO_DOMAIN}${NC}"
    elif [[ -n "$CLOUDFLARED_PATH" ]]; then
        echo -e "  Cloudflared: ${GREEN}已安装${NC} ${YELLOW}(未启用隧道)${NC}"
    else
        echo -e "  Cloudflared: ${YELLOW}未安装${NC}"
    fi
}

# ==================== 主菜单 ====================

show_main_menu() {
    print_banner
    load_current_config
    check_installation_status
    
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                     ${BOLD}主菜单${NC}                                  ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}1.${NC} 安装/重装服务端                                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}2.${NC} 配置 Cloudflare 隧道 (推荐) ⭐                        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}3.${NC} 配置传统证书 (需公网IP)                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}4.${NC} 配置域名                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}5.${NC} 生成/重置 Token                                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}6.${NC} 查看配置                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}7.${NC} 查看日志                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}8.${NC} 管理服务                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}9.${NC} Cloudflare IP 优选                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}10.${NC} 卸载                                                 ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}0.${NC} 退出                                                  ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    
    if [[ -n "$CURRENT_TOKEN" ]]; then
        echo -e "  Token: ${GREEN}${CURRENT_TOKEN:0:16}...${NC}"
    fi
    if [[ -n "$ARGO_DOMAIN" ]]; then
        echo -e "  Argo域名: ${GREEN}https://${ARGO_DOMAIN}${NC}"
    elif [[ -n "$CURRENT_DOMAIN" ]]; then
        echo -e "  域名: ${GREEN}${CURRENT_DOMAIN}${NC}"
    fi
    echo ""
}

# ==================== 1. 安装服务端 ====================

install_server() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                 安装 Phantom-X 服务端                        ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    require_root
    
    if [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        log_warn "检测到已安装的版本"
        if ! confirm "是否覆盖安装?"; then
            return
        fi
    fi
    
    # 检测系统
    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l) arch="arm" ;;
        *) die "不支持的架构: $arch" ;;
    esac
    
    log_step "系统: $os / $arch"
    
    # 获取版本
    log_step "获取最新版本..."
    local version
    version=$(curl -sL --connect-timeout 10 "${GITHUB_API_URL}/releases/latest" 2>/dev/null | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | sed 's/^v//' || echo "2.0.0")
    
    log_info "安装版本: v${version}"
    
    # 下载
    local download_url="${GITHUB_RELEASE_URL}/v${version}/${BINARY_NAME}-${os}-${arch}.tar.gz"
    local temp_dir
    temp_dir=$(mktemp -d)
    
    log_step "下载中..."
    if ! curl -fSL --progress-bar -o "${temp_dir}/server.tar.gz" "$download_url"; then
        rm -rf "$temp_dir"
        die "下载失败"
    fi
    
    # 解压安装
    log_step "解压安装..."
    tar -xzf "${temp_dir}/server.tar.gz" -C "$temp_dir" 2>/dev/null || die "解压失败"
    
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
    
    local binary_found=false
    for name in "${BINARY_NAME}" "phantom-x-server" "server"; do
        if [[ -f "${temp_dir}/${name}" ]]; then
            systemctl stop "$SERVICE_NAME" 2>/dev/null || true
            mv "${temp_dir}/${name}" "${INSTALL_DIR}/${BINARY_NAME}"
            chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
            ln -sf "${INSTALL_DIR}/${BINARY_NAME}" /usr/local/bin/phantom-x-server
            binary_found=true
            break
        fi
    done
    
    rm -rf "$temp_dir"
    
    if [[ "$binary_found" != "true" ]]; then
        die "未找到可执行文件"
    fi
    
    log_info "服务端安装成功"
    
    # 创建基础配置
    if [[ ! -f "${CONFIG_DIR}/server.yaml" ]]; then
        create_config_file
    fi
    
    # 创建 systemd 服务
    create_systemd_service
    
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}  下一步建议:${NC}"
    echo "    ${GREEN}2${NC} - 配置 Cloudflare 隧道（推荐，无需公网IP）"
    echo "    ${GREEN}3${NC} - 配置传统证书（如果有公网IP）"
    echo "    ${GREEN}5${NC} - 生成 Token"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    read -rp "输入数字继续，或按 Enter 返回: " next_action
    case "$next_action" in
        2) setup_cloudflare_tunnel ;;
        3) setup_certificate ;;
        5) generate_new_token ;;
        *) return ;;
    esac
}

# ==================== 2. Cloudflare 隧道 (核心功能) ====================

setup_cloudflare_tunnel() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}            配置 Cloudflare 临时隧道 ⭐                        ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${GREEN}优势:${NC}"
    echo "  ✓ 无需公网 IP"
    echo "  ✓ 自动获得 HTTPS 域名 (xxx.trycloudflare.com)"
    echo "  ✓ 免费 CDN 加速"
    echo "  ✓ 抗 DDoS 攻击"
    echo "  ✓ 隐藏真实 IP"
    echo ""
    
    if [[ "$ARGO_ENABLED" == true ]]; then
        echo -e "  当前 Argo 域名: ${GREEN}${ARGO_DOMAIN}${NC}"
        echo ""
        echo "操作:"
        echo "  1) 重新生成域名"
        echo "  2) 停止 Argo 隧道"
        echo "  3) 查看状态"
        echo "  4) 返回"
        echo ""
        read -rp "选择 [1-4]: " argo_action
        
        case "$argo_action" in
            1) reinstall_argo_tunnel ;;
            2) stop_argo_tunnel ;;
            3) show_argo_status ;;
            *) return ;;
        esac
        return
    fi
    
    if ! confirm "是否安装并启动 Cloudflare 隧道?"; then
        return
    fi
    
    require_root
    
    # 1. 安装 cloudflared
    install_cloudflared
    
    # 2. 配置本地服务监听（使用 localhost）
    log_step "配置本地服务..."
    
    # 修改配置为监听 localhost:8080
    if [[ -f "${CONFIG_DIR}/server.yaml" ]]; then
        sed -i 's/^listen:.*/listen: "127.0.0.1:8080"/' "${CONFIG_DIR}/server.yaml"
    else
        create_config_file "127.0.0.1:8080"
    fi
    
    # 3. 创建 Cloudflared 服务
    create_cloudflared_service
    
    # 4. 启动服务
    log_step "启动 Phantom-X 服务..."
    systemctl restart "$SERVICE_NAME"
    sleep 2
    
    log_step "启动 Cloudflare 隧道..."
    systemctl start cloudflared-phantom-x
    
    # 5. 等待获取域名
    log_step "等待隧道域名分配（最长30秒）..."
    local retry=0
    local max_retry=30
    ARGO_DOMAIN=""
    
    while [[ $retry -lt $max_retry ]]; do
        ARGO_DOMAIN=$(journalctl -u cloudflared-phantom-x -n 100 --no-pager 2>/dev/null | grep -oP 'https://[a-z0-9-]+\.trycloudflare\.com' | head -1 | sed 's|https://||')
        
        if [[ -n "$ARGO_DOMAIN" ]]; then
            echo "$ARGO_DOMAIN" > "${CONFIG_DIR}/argo_domain.txt"
            ARGO_ENABLED=true
            break
        fi
        
        sleep 1
        retry=$((retry + 1))
        echo -n "."
    done
    
    echo ""
    
    if [[ -n "$ARGO_DOMAIN" ]]; then
        systemctl enable cloudflared-phantom-x >/dev/null 2>&1
        
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${WHITE}${BOLD}  ✅ Cloudflare 隧道配置成功！${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "  隧道域名: ${GREEN}${BOLD}https://${ARGO_DOMAIN}${NC}"
        echo -e "  WebSocket: ${GREEN}wss://${ARGO_DOMAIN}/ws${NC}"
        echo ""
        echo -e "${YELLOW}  客户端配置:${NC}"
        echo -e "    server: ${GREEN}wss://${ARGO_DOMAIN}/ws${NC}"
        
        if [[ -n "$CURRENT_TOKEN" ]]; then
            echo -e "    token: ${GREEN}${CURRENT_TOKEN}${NC}"
        fi
        
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        
        if [[ -z "$CURRENT_TOKEN" ]]; then
            if confirm "是否现在生成 Token?"; then
                generate_new_token
            fi
        fi
    else
        log_error "获取隧道域名失败"
        echo ""
        log_step "查看 cloudflared 日志排查问题:"
        echo "  journalctl -u cloudflared-phantom-x -n 50"
    fi
    
    pause
}

install_cloudflared() {
    if [[ -n "$CLOUDFLARED_PATH" ]] && [[ -x "$CLOUDFLARED_PATH" ]]; then
        log_info "Cloudflared 已安装: $CLOUDFLARED_PATH"
        return
    fi
    
    log_step "安装 Cloudflared..."
    
    local os arch filename
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l) arch="arm" ;;
        *) die "不支持的架构: $arch" ;;
    esac
    
    case "$os" in
        linux) filename="cloudflared-${os}-${arch}" ;;
        darwin) filename="cloudflared-${os}-${arch}.tgz" ;;
        *) die "不支持的系统: $os" ;;
    esac
    
    local download_url="${CLOUDFLARED_RELEASE}/${filename}"
    local temp_file="/tmp/cloudflared_download"
    
    if ! curl -fSL --progress-bar -o "$temp_file" "$download_url"; then
        die "下载 cloudflared 失败"
    fi
    
    if [[ "$filename" == *.tgz ]]; then
        tar -xzf "$temp_file" -C /tmp/
        mv /tmp/cloudflared /usr/local/bin/cloudflared
    else
        mv "$temp_file" /usr/local/bin/cloudflared
    fi
    
    chmod +x /usr/local/bin/cloudflared
    CLOUDFLARED_PATH="/usr/local/bin/cloudflared"
    
    log_info "Cloudflared 安装完成"
}

create_cloudflared_service() {
    log_step "创建 Cloudflared systemd 服务..."
    
    cat > "$CLOUDFLARED_SERVICE" << EOF
[Unit]
Description=Cloudflared Tunnel for Phantom-X
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/cloudflared tunnel --url http://127.0.0.1:8080 --no-autoupdate --logfile ${LOG_DIR}/cloudflared.log
Restart=always
RestartSec=5
StartLimitInterval=0

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log_info "Cloudflared 服务已创建"
}

reinstall_argo_tunnel() {
    log_step "重新生成 Argo 域名..."
    
    systemctl stop cloudflared-phantom-x
    sleep 2
    
    rm -f "${CONFIG_DIR}/argo_domain.txt"
    rm -f "${LOG_DIR}/cloudflared.log"
    
    systemctl start cloudflared-phantom-x
    
    log_step "等待新域名..."
    sleep 5
    
    local retry=0
    while [[ $retry -lt 30 ]]; do
        ARGO_DOMAIN=$(journalctl -u cloudflared-phantom-x -n 100 --no-pager 2>/dev/null | grep -oP 'https://[a-z0-9-]+\.trycloudflare\.com' | head -1 | sed 's|https://||')
        
        if [[ -n "$ARGO_DOMAIN" ]]; then
            echo "$ARGO_DOMAIN" > "${CONFIG_DIR}/argo_domain.txt"
            log_info "新域名: https://${ARGO_DOMAIN}"
            break
        fi
        
        sleep 1
        retry=$((retry + 1))
    done
    
    if [[ -z "$ARGO_DOMAIN" ]]; then
        log_error "获取域名失败"
    fi
    
    pause
}

stop_argo_tunnel() {
    if ! confirm "确认停止 Argo 隧道?"; then
        return
    fi
    
    log_step "停止 Argo 隧道..."
    systemctl stop cloudflared-phantom-x
    systemctl disable cloudflared-phantom-x
    
    rm -f "${CONFIG_DIR}/argo_domain.txt"
    ARGO_ENABLED=false
    ARGO_DOMAIN=""
    
    log_info "Argo 隧道已停止"
    log_warn "服务端现在无法从外部访问，请配置传统证书或重新启用隧道"
    
    pause
}

show_argo_status() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                 Argo 隧道状态                                ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if systemctl is-active --quiet cloudflared-phantom-x; then
        echo -e "  状态: ${GREEN}运行中${NC}"
        echo -e "  域名: ${GREEN}https://${ARGO_DOMAIN}${NC}"
        echo ""
        
        systemctl status cloudflared-phantom-x --no-pager
        echo ""
        echo -e "${CYAN}最近日志:${NC}"
        journalctl -u cloudflared-phantom-x -n 20 --no-pager
    else
        echo -e "  状态: ${RED}已停止${NC}"
    fi
    
    pause
}

# ==================== 3. 传统证书配置 ====================

setup_certificate() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                配置传统 TLS 证书 (需公网IP)                  ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo "证书类型:"
    echo "  1) 自签名证书（测试）"
    echo "  2) Let's Encrypt 证书"
    echo "  3) 已有证书"
    echo "  4) 返回"
    echo ""
    read -rp "选择 [1-4]: " cert_choice
    
    case "$cert_choice" in
        1) generate_self_signed_cert ;;
        2) setup_letsencrypt_cert ;;
        3) use_existing_cert ;;
        *) return ;;
    esac
}

generate_self_signed_cert() {
    log_step "生成自签名证书..."
    
    local domain
    read -rp "域名 (默认: localhost): " domain
    domain="${domain:-localhost}"
    
    command_exists openssl || die "未安装 openssl"
    
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
CN = $domain

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $domain
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${CONFIG_DIR}/key.pem" \
        -out "${CONFIG_DIR}/cert.pem" \
        -config "$config_file" 2>/dev/null || die "证书生成失败"
    
    chmod 600 "${CONFIG_DIR}/key.pem"
    chmod 644 "${CONFIG_DIR}/cert.pem"
    rm -f "$config_file"
    
    log_info "自签名证书已生成"
    
    # 修改配置为监听公网端口
    sed -i 's/^listen:.*/listen: ":443"/' "${CONFIG_DIR}/server.yaml"
    
    pause
}

setup_letsencrypt_cert() {
    require_root
    
    command_exists certbot || {
        log_step "安装 certbot..."
        if command_exists apt-get; then
            apt-get update -qq && apt-get install -y -qq certbot
        elif command_exists yum; then
            yum install -y -q certbot
        else
            die "无法自动安装 certbot"
        fi
    }
    
    local domain email
    read -rp "域名: " domain
    read -rp "邮箱: " email
    
    [[ -z "$domain" ]] || [[ -z "$email" ]] && die "域名和邮箱不能为空"
    
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    
    if certbot certonly --standalone -d "$domain" --email "$email" --agree-tos --non-interactive; then
        ln -sf "/etc/letsencrypt/live/${domain}/fullchain.pem" "${CONFIG_DIR}/cert.pem"
        ln -sf "/etc/letsencrypt/live/${domain}/privkey.pem" "${CONFIG_DIR}/key.pem"
        
        log_info "证书配置成功"
        
        # 自动续期
        (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook 'systemctl reload $SERVICE_NAME'") | crontab -
    fi
    
    pause
}

use_existing_cert() {
    local cert_path key_path
    read -rp "证书路径: " cert_path
    read -rp "私钥路径: " key_path
    
    [[ -f "$cert_path" ]] || die "证书文件不存在"
    [[ -f "$key_path" ]] || die "私钥文件不存在"
    
    cp "$cert_path" "${CONFIG_DIR}/cert.pem"
    cp "$key_path" "${CONFIG_DIR}/key.pem"
    chmod 644 "${CONFIG_DIR}/cert.pem"
    chmod 600 "${CONFIG_DIR}/key.pem"
    
    log_info "证书已配置"
    pause
}

# ==================== 4. 域名配置 ====================

setup_domain() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                      配置域名                                ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [[ -n "$ARGO_DOMAIN" ]]; then
        log_info "当前使用 Argo 隧道域名: $ARGO_DOMAIN"
        log_warn "使用 Argo 模式时无需手动配置域名"
        pause
        return
    fi
    
    local domain
    read -rp "域名 (留空使用临时域名): " domain
    
    if [[ -z "$domain" ]]; then
        local public_ip
        public_ip=$(curl -s https://api.ipify.org 2>/dev/null || echo "127.0.0.1")
        domain="${public_ip}.nip.io"
        log_info "临时域名: $domain"
    fi
    
    echo "$domain" > "${CONFIG_DIR}/domain.txt"
    CURRENT_DOMAIN="$domain"
    
    log_info "域名已设置: $domain"
    
    echo ""
    echo -e "${YELLOW}DNS 配置:${NC}"
    echo "  A 记录指向: $(curl -s https://api.ipify.org 2>/dev/null)"
    echo ""
    
    pause
}

# ==================== 5. Token 生成 ====================

generate_new_token() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                   生成/重置 Token                            ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [[ -n "$CURRENT_TOKEN" ]]; then
        echo -e "  当前 Token: ${YELLOW}${CURRENT_TOKEN}${NC}"
        echo ""
        confirm "是否重新生成?" || return
    fi
    
    local new_token
    new_token=$(generate_token)
    CURRENT_TOKEN="$new_token"
    
    if [[ -f "${CONFIG_DIR}/server.yaml" ]]; then
        sed -i "s/^token:.*/token: \"$new_token\"/" "${CONFIG_DIR}/server.yaml"
    else
        create_config_file
    fi
    
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}${BOLD}  新 Token: ${GREEN}${new_token}${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        if confirm "服务运行中，是否重启?"; then
            systemctl restart "$SERVICE_NAME"
        fi
    fi
    
    pause
}

# ==================== 6. 查看配置 ====================

show_config() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                     当前配置                                 ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [[ ! -f "${CONFIG_DIR}/server.yaml" ]]; then
        log_warn "配置文件不存在"
        if confirm "是否创建?"; then
            create_config_file
        fi
        return
    fi
    
    cat "${CONFIG_DIR}/server.yaml"
    
    echo ""
    if [[ -n "$ARGO_DOMAIN" ]]; then
        echo -e "Argo 域名: ${GREEN}https://${ARGO_DOMAIN}${NC}"
    fi
    
    pause
}

# ==================== 7. 日志 ====================

show_logs() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                     服务日志                                 ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo "日志选项:"
    echo "  1) Phantom-X 实时日志"
    echo "  2) Cloudflared 实时日志"
    echo "  3) Phantom-X 最近 50 行"
    echo "  4) Cloudflared 最近 50 行"
    echo "  5) 返回"
    echo ""
    read -rp "选择 [1-5]: " log_choice
    
    case "$log_choice" in
        1) journalctl -u "$SERVICE_NAME" -f ;;
        2) journalctl -u cloudflared-phantom-x -f ;;
        3) journalctl -u "$SERVICE_NAME" -n 50 --no-pager; pause; show_logs ;;
        4) journalctl -u cloudflared-phantom-x -n 50 --no-pager; pause; show_logs ;;
        *) return ;;
    esac
}

# ==================== 8. 服务管理 ====================

manage_service() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                     服务管理                                 ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "  Phantom-X: ${GREEN}运行中${NC}"
    else
        echo -e "  Phantom-X: ${YELLOW}已停止${NC}"
    fi
    
    if systemctl is-active --quiet cloudflared-phantom-x 2>/dev/null; then
        echo -e "  Cloudflared: ${GREEN}运行中${NC}"
    else
        echo -e "  Cloudflared: ${YELLOW}已停止${NC}"
    fi
    
    echo ""
    echo "操作:"
    echo "  1) 启动所有服务"
    echo "  2) 停止所有服务"
    echo "  3) 重启所有服务"
    echo "  4) 查看状态"
    echo "  5) 返回"
    echo ""
    read -rp "选择 [1-5]: " service_action
    
    case "$service_action" in
        1)
            systemctl start "$SERVICE_NAME"
            systemctl start cloudflared-phantom-x 2>/dev/null || true
            log_info "服务已启动"
            pause
            manage_service
            ;;
        2)
            systemctl stop "$SERVICE_NAME"
            systemctl stop cloudflared-phantom-x 2>/dev/null || true
            log_info "服务已停止"
            pause
            manage_service
            ;;
        3)
            systemctl restart "$SERVICE_NAME"
            systemctl restart cloudflared-phantom-x 2>/dev/null || true
            log_info "服务已重启"
            pause
            manage_service
            ;;
        4)
            systemctl status "$SERVICE_NAME" --no-pager
            echo ""
            systemctl status cloudflared-phantom-x --no-pager 2>/dev/null || true
            pause
            manage_service
            ;;
        *) return ;;
    esac
}

# ==================== 9. IP 优选 ====================

optimize_cloudflare_ip() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}              Cloudflare IP 优选 (客户端功能)                ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_info "此功能由客户端自动执行"
    echo ""
    echo "客户端配置示例:"
    echo "  enable_cf_optimize: true"
    echo "  cf_optimize_count: 200"
    echo "  cf_optimize_interval: 30m"
    echo ""
    echo "手动指定 IP:"
    echo "  preferred_cf_ip: \"104.16.1.1\""
    echo ""
    
    pause
}

# ==================== 10. 卸载 ====================

uninstall_server() {
    clear
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║${NC}                      卸载服务                                ${RED}║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    confirm "${RED}确认卸载?${NC}" || return
    
    require_root
    
    systemctl stop "$SERVICE_NAME" cloudflared-phantom-x 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" cloudflared-phantom-x 2>/dev/null || true
    
    rm -f "$SYSTEMD_SERVICE" "$CLOUDFLARED_SERVICE"
    systemctl daemon-reload
    
    rm -rf "$INSTALL_DIR" "$LOG_DIR"
    rm -f /usr/local/bin/phantom-x-server
    
    if confirm "删除配置文件?"; then
        rm -rf "$CONFIG_DIR"
    fi
    
    log_info "卸载完成"
    pause
}

# ==================== 辅助函数 ====================

create_config_file() {
    local listen="${1:-:443}"
    local token="${CURRENT_TOKEN:-$(generate_token)}"
    CURRENT_TOKEN="$token"
    
    mkdir -p "$CONFIG_DIR"
    
    cat > "${CONFIG_DIR}/server.yaml" << EOF
# Phantom-X 服务端配置
listen: "${listen}"
cert: "${CONFIG_DIR}/cert.pem"
key: "${CONFIG_DIR}/key.pem"
token: "${token}"
ws_path: "/ws"

max_streams_per_conn: 1000
read_timeout: 60s
write_timeout: 10s
idle_timeout: 120s
log_level: "info"
EOF
    
    chmod 600 "${CONFIG_DIR}/server.yaml"
    log_info "配置已创建"
}

create_systemd_service() {
    cat > "$SYSTEMD_SERVICE" << EOF
[Unit]
Description=Phantom-X Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -c ${CONFIG_DIR}/server.yaml
Restart=always
RestartSec=3

LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
}

# ==================== 主循环 ====================

main_loop() {
    while true; do
        show_main_menu
        
        read -rp "请选择 [0-10]: " choice
        
        case "$choice" in
            1) install_server ;;
            2) setup_cloudflare_tunnel ;;
            3) setup_certificate ;;
            4) setup_domain ;;
            5) generate_new_token ;;
            6) show_config ;;
            7) show_logs ;;
            8) manage_service ;;
            9) optimize_cloudflare_ip ;;
            10) uninstall_server ;;
            0) log_info "再见！"; exit 0 ;;
            *) log_warn "无效选项"; sleep 1 ;;
        esac
    done
}

# ==================== 入口 ====================

if [[ $# -gt 0 ]]; then
    case "$1" in
        server|install) install_server ;;
        tunnel|argo) setup_cloudflare_tunnel ;;
        uninstall) uninstall_server ;;
        *) echo "用法: $0 [server|tunnel|uninstall]"; exit 1 ;;
    esac
else
    main_loop
fi
