#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#                     Phantom-X 交互式安装脚本 v2.0
#                     简化部署 · 一键配置 · 智能管理
#═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

# ==================== 全局变量 ====================
readonly SCRIPT_VERSION="2.0.0"
readonly INSTALL_DIR="/opt/phantom-x"
readonly CONFIG_DIR="/etc/phantom-x"
readonly LOG_DIR="/var/log/phantom-x"
readonly SERVICE_NAME="phantom-x-server"
readonly BINARY_NAME="phantom-x-server"
readonly SYSTEMD_SERVICE="/etc/systemd/system/${SERVICE_NAME}.service"

# GitHub 仓库信息
readonly GITHUB_REPO="mrcgq/pxx"
readonly GITHUB_API_URL="https://api.github.com/repos/${GITHUB_REPO}"
readonly GITHUB_RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/download"

# 颜色定义
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

# ==================== 工具函数 ====================

log_info()  { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step()  { echo -e "${BLUE}[→]${NC} $1"; }

die() { log_error "$1"; exit "${2:-1}"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

is_root() { [[ $EUID -eq 0 ]]; }

require_root() {
    if ! is_root; then
        die "请使用 root 权限运行，或使用 sudo"
    fi
}

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
║                                                              ║
║   ____  __                  __                        _  __  ║
║  / __ \/ /_  ____ _____  / /_____  ____ ___        | |/ /  ║
║ / /_/ / __ \/ __ `/ __ \/ __/ __ \/ __ `__ \  ____ \   /   ║
║/ ____/ / / / /_/ / / / / /_/ /_/ / / / / / / /_____/   |    ║
║_/   /_/ /_/\__,_/_/ /_/\__/\____/_/ /_/ /_/       /_/|_|    ║
║                                                              ║
║              高性能隧道代理 - 交互式安装工具 v2.0              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# ==================== 状态检查 ====================

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
    
    echo -e "  状态: $status"
}

load_current_config() {
    if [[ -f "${CONFIG_DIR}/server.yaml" ]]; then
        CURRENT_TOKEN=$(grep "^token:" "${CONFIG_DIR}/server.yaml" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo "")
        CURRENT_PORT=$(grep "^listen:" "${CONFIG_DIR}/server.yaml" 2>/dev/null | awk -F: '{print $NF}' | tr -d '" ' || echo "443")
    fi
    
    if [[ -f "${CONFIG_DIR}/domain.txt" ]]; then
        CURRENT_DOMAIN=$(cat "${CONFIG_DIR}/domain.txt")
    fi
}

# ==================== 主菜单 ====================

show_main_menu() {
    print_banner
    check_installation_status
    load_current_config
    
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                     ${BOLD}主菜单${NC}                                  ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}1.${NC} 安装/重装服务端                                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}2.${NC} 配置证书                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}3.${NC} 配置域名                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}4.${NC} 生成/重置 Token                                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}5.${NC} 查看配置                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}6.${NC} 查看日志                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}7.${NC} 管理服务 (启动/停止/重启/状态)                         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}8.${NC} 卸载服务端                                            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}9.${NC} 退出                                                  ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    
    if [[ -n "$CURRENT_TOKEN" ]]; then
        echo -e "  当前 Token: ${GREEN}${CURRENT_TOKEN:0:16}...${NC}"
    fi
    if [[ -n "$CURRENT_DOMAIN" ]]; then
        echo -e "  当前域名: ${GREEN}${CURRENT_DOMAIN}${NC}"
    fi
    echo -e "  当前端口: ${GREEN}${CURRENT_PORT}${NC}"
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
    
    # 检查是否已安装
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
    version=$(curl -sL --connect-timeout 10 "${GITHUB_API_URL}/releases/latest" 2>/dev/null | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | sed 's/^v//' || echo "")
    
    if [[ -z "$version" ]]; then
        log_warn "无法获取最新版本，使用默认版本 2.0.0"
        version="2.0.0"
    else
        log_info "最新版本: v${version}"
    fi
    
    # 下载
    local download_url="${GITHUB_RELEASE_URL}/v${version}/${BINARY_NAME}-${os}-${arch}.tar.gz"
    local temp_dir
    temp_dir=$(mktemp -d)
    
    log_step "下载中..."
    if ! curl -fSL --progress-bar --connect-timeout 30 --max-time 300 -o "${temp_dir}/server.tar.gz" "$download_url"; then
        rm -rf "$temp_dir"
        die "下载失败，请检查网络或手动下载: $download_url"
    fi
    
    # 解压
    log_step "解压安装..."
    if ! tar -xzf "${temp_dir}/server.tar.gz" -C "$temp_dir" 2>/dev/null; then
        rm -rf "$temp_dir"
        die "解压失败"
    fi
    
    # 安装
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
    
    # 询问是否继续配置
    echo ""
    echo -e "${YELLOW}下一步建议:${NC}"
    echo "  1) 配置证书（选项 2）"
    echo "  2) 配置域名（选项 3）"
    echo "  3) 生成 Token（选项 4）"
    echo "  4) 启动服务（选项 7）"
    echo ""
    
    read -rp "输入数字继续配置，或按 Enter 返回菜单: " next_action
    case "$next_action" in
        2) setup_certificate ;;
        3) setup_domain ;;
        4) generate_new_token ;;
        7) manage_service ;;
        *) return ;;
    esac
}

# ==================== 2. 配置证书 ====================

setup_certificate() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                    配置 TLS 证书                             ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo "请选择证书类型:"
    echo "  1) 自签名证书（测试用）"
    echo "  2) Let's Encrypt 证书（推荐）"
    echo "  3) 使用已有证书"
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
    read -rp "输入域名 (默认: localhost): " domain
    domain="${domain:-localhost}"
    
    if ! command_exists openssl; then
        die "未安装 openssl"
    fi
    
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
DNS.3 = *.${domain}
IP.1 = 127.0.0.1
EOF
    
    if openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${CONFIG_DIR}/key.pem" \
        -out "${CONFIG_DIR}/cert.pem" \
        -config "$config_file" 2>/dev/null; then
        
        chmod 600 "${CONFIG_DIR}/key.pem"
        chmod 644 "${CONFIG_DIR}/cert.pem"
        rm -f "$config_file"
        
        log_info "自签名证书已生成"
        log_warn "⚠️  自签名证书仅用于测试，生产环境请使用正式证书"
    else
        rm -f "$config_file"
        die "证书生成失败"
    fi
    
    echo ""
    read -rp "输入数字继续，或按 Enter 返回: " next
    case "$next" in
        3) setup_domain ;;
        4) generate_new_token ;;
        5) show_config ;;
        *) return ;;
    esac
}

setup_letsencrypt_cert() {
    log_step "配置 Let's Encrypt 证书..."
    
    if ! command_exists certbot; then
        log_warn "未安装 certbot"
        if confirm "是否自动安装 certbot?"; then
            if command_exists apt-get; then
                apt-get update -qq && apt-get install -y -qq certbot
            elif command_exists yum; then
                yum install -y -q certbot
            else
                die "无法自动安装 certbot，请手动安装"
            fi
        else
            return
        fi
    fi
    
    local domain email
    read -rp "输入域名: " domain
    read -rp "输入邮箱: " email
    
    if [[ -z "$domain" ]] || [[ -z "$email" ]]; then
        log_error "域名和邮箱不能为空"
        return
    fi
    
    log_step "申请证书（需要暂停服务）..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    
    if certbot certonly --standalone -d "$domain" --email "$email" --agree-tos --non-interactive; then
        ln -sf "/etc/letsencrypt/live/${domain}/fullchain.pem" "${CONFIG_DIR}/cert.pem"
        ln -sf "/etc/letsencrypt/live/${domain}/privkey.pem" "${CONFIG_DIR}/key.pem"
        
        log_info "Let's Encrypt 证书配置成功"
        
        # 设置自动续期
        if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
            (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook 'systemctl reload $SERVICE_NAME'") | crontab -
            log_info "已设置自动续期（每天凌晨3点）"
        fi
    else
        log_error "证书申请失败"
    fi
    
    pause
}

use_existing_cert() {
    log_step "使用已有证书..."
    
    local cert_path key_path
    read -rp "证书文件路径: " cert_path
    read -rp "私钥文件路径: " key_path
    
    if [[ ! -f "$cert_path" ]]; then
        log_error "证书文件不存在: $cert_path"
        return
    fi
    
    if [[ ! -f "$key_path" ]]; then
        log_error "私钥文件不存在: $key_path"
        return
    fi
    
    cp "$cert_path" "${CONFIG_DIR}/cert.pem"
    cp "$key_path" "${CONFIG_DIR}/key.pem"
    chmod 644 "${CONFIG_DIR}/cert.pem"
    chmod 600 "${CONFIG_DIR}/key.pem"
    
    log_info "证书已复制到 ${CONFIG_DIR}/"
    pause
}

# ==================== 3. 配置域名 ====================

setup_domain() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                      配置域名                                ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [[ -n "$CURRENT_DOMAIN" ]]; then
        echo -e "  当前域名: ${GREEN}${CURRENT_DOMAIN}${NC}"
        echo ""
    fi
    
    local domain
    read -rp "输入域名 (留空使用临时域名): " domain
    
    if [[ -z "$domain" ]]; then
        # 使用 IP + nip.io
        local public_ip
        public_ip=$(curl -s https://api.ipify.org 2>/dev/null || curl -s https://ifconfig.me 2>/dev/null || echo "127.0.0.1")
        domain="${public_ip}.nip.io"
        log_info "使用临时域名: $domain"
    fi
    
    echo "$domain" > "${CONFIG_DIR}/domain.txt"
    CURRENT_DOMAIN="$domain"
    
    log_info "域名已设置: $domain"
    
    # 更新配置
    if [[ -f "${CONFIG_DIR}/server.yaml" ]]; then
        log_step "更新配置文件..."
        update_config_file
    else
        log_warn "配置文件不存在，请先生成配置"
    fi
    
    echo ""
    echo -e "${YELLOW}DNS 配置提示:${NC}"
    echo "  将域名 A 记录指向: $(curl -s https://api.ipify.org 2>/dev/null || echo '服务器IP')"
    echo ""
    
    read -rp "输入数字继续，或按 Enter 返回: " next
    case "$next" in
        2) setup_certificate ;;
        4) generate_new_token ;;
        7) manage_service ;;
        *) return ;;
    esac
}

# ==================== 4. 生成 Token ====================

generate_new_token() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                   生成/重置 Token                            ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [[ -n "$CURRENT_TOKEN" ]]; then
        echo -e "  当前 Token: ${YELLOW}${CURRENT_TOKEN}${NC}"
        echo ""
        if ! confirm "是否重新生成 Token?"; then
            return
        fi
    fi
    
    local new_token
    new_token=$(generate_token)
    CURRENT_TOKEN="$new_token"
    
    log_info "新 Token: ${GREEN}${new_token}${NC}"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}${BOLD}  请妥善保管此 Token，客户端连接时需要使用！${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # 更新配置文件
    if [[ -f "${CONFIG_DIR}/server.yaml" ]]; then
        sed -i "s/^token:.*/token: \"$new_token\"/" "${CONFIG_DIR}/server.yaml"
        log_info "配置文件已更新"
        
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            if confirm "服务正在运行，是否重启以应用新 Token?"; then
                systemctl restart "$SERVICE_NAME"
                log_info "服务已重启"
            fi
        fi
    else
        # 创建完整配置
        create_config_file
    fi
    
    echo ""
    read -rp "输入数字继续，或按 Enter 返回: " next
    case "$next" in
        5) show_config ;;
        7) manage_service ;;
        *) return ;;
    esac
}

# ==================== 5. 查看配置 ====================

show_config() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                     当前配置                                 ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [[ ! -f "${CONFIG_DIR}/server.yaml" ]]; then
        log_warn "配置文件不存在"
        if confirm "是否现在创建?"; then
            create_config_file
        fi
        return
    fi
    
    echo -e "${WHITE}配置文件:${NC} ${CONFIG_DIR}/server.yaml"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    cat "${CONFIG_DIR}/server.yaml"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    if [[ -f "${CONFIG_DIR}/cert.pem" ]]; then
        log_info "证书: ${CONFIG_DIR}/cert.pem"
        openssl x509 -in "${CONFIG_DIR}/cert.pem" -noout -subject -dates 2>/dev/null || true
    else
        log_warn "未配置证书"
    fi
    
    echo ""
    echo "操作选项:"
    echo "  1) 编辑配置"
    echo "  2) 重新生成 Token"
    echo "  3) 返回"
    echo ""
    read -rp "选择 [1-3]: " config_action
    
    case "$config_action" in
        1)
            if command_exists nano; then
                nano "${CONFIG_DIR}/server.yaml"
            elif command_exists vi; then
                vi "${CONFIG_DIR}/server.yaml"
            else
                log_error "未找到文本编辑器"
            fi
            show_config
            ;;
        2)
            generate_new_token
            ;;
        *)
            return
            ;;
    esac
}

# ==================== 6. 查看日志 ====================

show_logs() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                     服务日志                                 ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo "日志选项:"
    echo "  1) 实时日志（跟踪）"
    echo "  2) 最近 50 行"
    echo "  3) 最近 100 行"
    echo "  4) 全部日志"
    echo "  5) 返回"
    echo ""
    read -rp "选择 [1-5]: " log_choice
    
    case "$log_choice" in
        1)
            echo ""
            log_step "实时日志（按 Ctrl+C 退出）"
            journalctl -u "$SERVICE_NAME" -f
            ;;
        2)
            journalctl -u "$SERVICE_NAME" -n 50 --no-pager
            pause
            show_logs
            ;;
        3)
            journalctl -u "$SERVICE_NAME" -n 100 --no-pager
            pause
            show_logs
            ;;
        4)
            journalctl -u "$SERVICE_NAME" --no-pager
            pause
            show_logs
            ;;
        *)
            return
            ;;
    esac
}

# ==================== 7. 管理服务 ====================

manage_service() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                     服务管理                                 ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # 检查服务状态
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo -e "  服务状态: ${GREEN}运行中${NC}"
    else
        echo -e "  服务状态: ${YELLOW}已停止${NC}"
    fi
    
    echo ""
    echo "服务操作:"
    echo "  1) 启动服务"
    echo "  2) 停止服务"
    echo "  3) 重启服务"
    echo "  4) 查看状态"
    echo "  5) 开机自启（启用/禁用）"
    echo "  6) 创建/重建 systemd 服务"
    echo "  7) 返回"
    echo ""
    read -rp "选择 [1-7]: " service_action
    
    case "$service_action" in
        1)
            log_step "启动服务..."
            if systemctl start "$SERVICE_NAME"; then
                log_info "服务已启动"
                sleep 2
                systemctl status "$SERVICE_NAME" --no-pager
            else
                log_error "启动失败"
            fi
            pause
            manage_service
            ;;
        2)
            log_step "停止服务..."
            if systemctl stop "$SERVICE_NAME"; then
                log_info "服务已停止"
            else
                log_error "停止失败"
            fi
            pause
            manage_service
            ;;
        3)
            log_step "重启服务..."
            if systemctl restart "$SERVICE_NAME"; then
                log_info "服务已重启"
                sleep 2
                systemctl status "$SERVICE_NAME" --no-pager
            else
                log_error "重启失败"
            fi
            pause
            manage_service
            ;;
        4)
            systemctl status "$SERVICE_NAME" --no-pager
            pause
            manage_service
            ;;
        5)
            if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
                if confirm "当前已启用开机自启，是否禁用?"; then
                    systemctl disable "$SERVICE_NAME"
                    log_info "已禁用开机自启"
                fi
            else
                if confirm "是否启用开机自启?"; then
                    systemctl enable "$SERVICE_NAME"
                    log_info "已启用开机自启"
                fi
            fi
            pause
            manage_service
            ;;
        6)
            create_systemd_service
            manage_service
            ;;
        *)
            return
            ;;
    esac
}

# ==================== 8. 卸载 ====================

uninstall_server() {
    clear
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║${NC}                      卸载服务端                              ${RED}║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_warn "此操作将删除:"
    echo "  - 程序文件: $INSTALL_DIR"
    echo "  - 日志文件: $LOG_DIR"
    echo "  - Systemd 服务"
    echo ""
    echo -e "${YELLOW}配置文件将保留在: $CONFIG_DIR${NC}"
    echo ""
    
    if ! confirm "${RED}确认卸载?${NC}"; then
        return
    fi
    
    require_root
    
    # 停止服务
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_step "停止服务..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    # 禁用服务
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_step "禁用服务..."
        systemctl disable "$SERVICE_NAME"
    fi
    
    # 删除服务文件
    if [[ -f "$SYSTEMD_SERVICE" ]]; then
        rm -f "$SYSTEMD_SERVICE"
        systemctl daemon-reload
        log_info "已删除 systemd 服务"
    fi
    
    # 删除程序
    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
        log_info "已删除程序目录"
    fi
    
    # 删除日志
    if [[ -d "$LOG_DIR" ]]; then
        rm -rf "$LOG_DIR"
        log_info "已删除日志目录"
    fi
    
    # 删除软链接
    rm -f /usr/local/bin/phantom-x-server
    
    log_info "卸载完成"
    
    if confirm "是否也删除配置文件?"; then
        rm -rf "$CONFIG_DIR"
        log_info "已删除配置目录"
    else
        log_info "配置文件保留在: $CONFIG_DIR"
    fi
    
    pause
}

# ==================== 辅助函数：创建配置 ====================

create_config_file() {
    log_step "创建配置文件..."
    
    local port="${CURRENT_PORT:-443}"
    local token="${CURRENT_TOKEN:-$(generate_token)}"
    CURRENT_TOKEN="$token"
    
    mkdir -p "$CONFIG_DIR"
    
    cat > "${CONFIG_DIR}/server.yaml" << EOF
# Phantom-X 服务端配置
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

listen: ":${port}"
cert: "${CONFIG_DIR}/cert.pem"
key: "${CONFIG_DIR}/key.pem"
token: "${token}"
ws_path: "/ws"

# 性能调优
max_streams_per_conn: 1000
read_timeout: 60s
write_timeout: 10s
idle_timeout: 120s

# 日志
log_level: "info"
EOF
    
    chmod 600 "${CONFIG_DIR}/server.yaml"
    log_info "配置文件已创建: ${CONFIG_DIR}/server.yaml"
    
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}  认证 Token: ${GREEN}${token}${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

update_config_file() {
    if [[ ! -f "${CONFIG_DIR}/server.yaml" ]]; then
        create_config_file
        return
    fi
    
    if [[ -n "$CURRENT_DOMAIN" ]] && ! grep -q "# Domain: $CURRENT_DOMAIN" "${CONFIG_DIR}/server.yaml"; then
        sed -i "1i# Domain: $CURRENT_DOMAIN" "${CONFIG_DIR}/server.yaml"
    fi
}

create_systemd_service() {
    require_root
    
    if [[ ! -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        log_error "服务端未安装，请先安装"
        return
    fi
    
    if [[ ! -f "${CONFIG_DIR}/server.yaml" ]]; then
        log_warn "配置文件不存在，正在创建..."
        create_config_file
    fi
    
    log_step "创建 systemd 服务..."
    
    cat > "$SYSTEMD_SERVICE" << EOF
[Unit]
Description=Phantom-X Server - High Performance Tunnel Proxy
Documentation=https://github.com/${GITHUB_REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -c ${CONFIG_DIR}/server.yaml
Restart=always
RestartSec=3
StartLimitInterval=60
StartLimitBurst=5

LimitNOFILE=1048576
LimitNPROC=512

StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log_info "Systemd 服务已创建"
    
    if confirm "是否启用开机自启?"; then
        systemctl enable "$SERVICE_NAME"
        log_info "已启用开机自启"
    fi
}

# ==================== 主循环 ====================

main_loop() {
    while true; do
        show_main_menu
        
        read -rp "请选择 [1-9]: " choice
        
        case "$choice" in
            1) install_server ;;
            2) setup_certificate ;;
            3) setup_domain ;;
            4) generate_new_token ;;
            5) show_config ;;
            6) show_logs ;;
            7) manage_service ;;
            8) uninstall_server ;;
            9)
                echo ""
                log_info "感谢使用 Phantom-X！"
                exit 0
                ;;
            *)
                log_warn "无效选项，请输入 1-9"
                sleep 1
                ;;
        esac
    done
}

# ==================== 入口 ====================

# 检查是否以参数方式调用（兼容旧版）
if [[ $# -gt 0 ]]; then
    case "$1" in
        server|install) install_server ;;
        uninstall) uninstall_server ;;
        *) 
            echo "用法: $0 [server|uninstall]"
            echo "或直接运行进入交互模式: $0"
            exit 1
            ;;
    esac
else
    # 交互模式
    main_loop
fi
