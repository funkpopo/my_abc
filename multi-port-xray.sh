#!/bin/bash

# 等待1秒, 避免curl下载脚本的打印与脚本本身的显示冲突
sleep 1

echo -e "                     _ ___                   \n ___ ___ __ __ ___ _| |  _|___ __ __   _ ___ \n|-_ |_  |  |  |-_ | _ |   |- _|  |  |_| |_  |\n|___|___|  _  |___|___|_|_|___|  _  |___|___|\n        |_____|               |_____|        "
red='\e[91m'
green='\e[92m'
yellow='\e[93m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'

# 脚本版本
VERSION="1.3.3"

# 配置文件路径
CONFIG_FILE="/usr/local/etc/xray/config.json"
CONFIG_DIR="/usr/local/etc/xray"
PORT_INFO_FILE="$HOME/.xray_port_info.json"
LOG_FILE="$HOME/.xray_management.log"

# 检查是否以root权限运行
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${red}错误: 必须以root权限运行此脚本${none}"
        exit 1
    fi
}

# 记录日志
log() {
    local level=$1
    local message=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# 添加日志记录函数的包装
log_info() {
    log "INFO" "$1"
}

log_error() {
    log "ERROR" "$1"
}

log_warn() {
    log "WARN" "$1"
}

# TCP优化函数
optimize_tcp() {
    echo -e "${yellow}正在优化TCP连接参数...${none}"
    log_info "开始优化TCP连接参数"
    
    # 备份原始配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)
    
    # 设置TCP Fast Open
    echo 3 > /proc/sys/net/ipv4/tcp_fastopen
    
    # 调整TCP缓冲区和连接参数
    cat >> /etc/sysctl.conf << EOF
# TCP优化参数
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_mtu_probing = 1
EOF
    
    # 应用配置
    sysctl -p > /dev/null 2>&1
    
    log_info "TCP优化完成"
}

# 获取公共IP的函数
get_public_ip() {
    local ip_type=$1  # 4 for IPv4, 6 for IPv6
    local interface=$2
    local timeout=3

    # IP检测源列表
    local ip_apis=(
        "https://www.cloudflare.com/cdn-cgi/trace"    # Cloudflare
        "https://api.ipify.org"                       # ipify
        "https://ip.sb"                               # ip.sb
        "https://api.ip.sb/ip"                        # ip.sb alternative
        "https://ifconfig.me"                         # ifconfig.me
    )

    for api in "${ip_apis[@]}"; do
        local ip
        if [[ $api == "https://www.cloudflare.com/cdn-cgi/trace" ]]; then
            ip=$(curl -"${ip_type}"s --interface "$interface" -m "$timeout" "$api" 2>/dev/null | grep -oP "ip=\K.*$")
        else
            ip=$(curl -"${ip_type}"s --interface "$interface" -m "$timeout" "$api" 2>/dev/null)
        fi

        if [[ -n "$ip" && $ip =~ ^[0-9a-fA-F:.]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done

    return 1
}

# 获取本机IP
get_local_ips() {
    local success=false
    IPv4=""
    IPv6=""
    
    # 获取网络接口列表
    InFaces=($(ls /sys/class/net/ | grep -E '^(eth|ens|eno|esp|enp|venet|vif)'))
    
    for i in "${InFaces[@]}"; do
        echo -e "${yellow}正在检测接口 $i ...${none}"
        
        # 尝试获取IPv4
        if [[ -z "$IPv4" ]]; then
            Public_IPv4=$(get_public_ip 4 "$i")
            if [[ -n "$Public_IPv4" ]]; then
                IPv4="$Public_IPv4"
                echo -e "${green}在接口 $i 上成功获取到IPv4: $IPv4${none}"
                log_info "获取到IPv4: $IPv4 (接口: $i)"
                success=true
            fi
        fi
        
        # 尝试获取IPv6
        if [[ -z "$IPv6" ]]; then
            Public_IPv6=$(get_public_ip 6 "$i")
            if [[ -n "$Public_IPv6" ]]; then
                IPv6="$Public_IPv6"
                echo -e "${green}在接口 $i 上成功获取到IPv6: $IPv6${none}"
                log_info "获取到IPv6: $IPv6 (接口: $i)"
                success=true
            fi
        fi
        
        # 如果两种IP都已获取到，可以提前退出循环
        if [[ -n "$IPv4" && -n "$IPv6" ]]; then
            break
        fi
    done

    # 如果通过网络接口获取失败，尝试直接获取
    if [[ -z "$IPv4" ]]; then
        echo -e "${yellow}尝试直接获取IPv4...${none}"
        IPv4=$(get_public_ip 4)
        if [[ -n "$IPv4" ]]; then
            echo -e "${green}成功获取到IPv4: $IPv4${none}"
            log_info "直接获取到IPv4: $IPv4"
            success=true
        fi
    fi
    
    if [[ -z "$IPv6" ]]; then
        echo -e "${yellow}尝试直接获取IPv6...${none}"
        IPv6=$(get_public_ip 6)
        if [[ -n "$IPv6" ]]; then
            echo -e "${green}成功获取到IPv6: $IPv6${none}"
            log_info "直接获取到IPv6: $IPv6"
            success=true
        fi
    fi

    # 检查是否获取到任何IP
    if ! $success; then
        echo -e "${red}警告: 未能获取到任何公共IP地址${none}"
        log_error "未能获取到任何公共IP地址"
        echo -e "${yellow}请检查:${none}"
        echo "1. 网络连接是否正常"
        echo "2. 是否有防火墙限制"
        echo "3. 服务器是否支持公网IP"
        echo "4. DNS设置是否正确"
        return 1
    fi

    return 0
}

error() {
    echo -e "\n$red 输入错误! $none\n"
    log_error "用户输入错误"
}

warn() {
    echo -e "\n$yellow $1 $none\n"
    log_warn "$1"
}

success() {
    echo -e "\n$green $1 $none\n"
    log_info "$1"
}

pause() {
    read -rsp "$(echo -e "按 $green Enter 回车键 $none 继续....或按 $red Ctrl + C $none 取消.")" -d $'\n'
    echo
}

# 创建必要的目录和文件
init_directories() {
    # 创建配置目录
    if [[ ! -d "$CONFIG_DIR" ]]; then
        mkdir -p "$CONFIG_DIR"
    fi
    
    # 初始化配置文件
    if [[ ! -f "$PORT_INFO_FILE" ]]; then
        echo '{"ports":[]}' > "$PORT_INFO_FILE"
        chmod 600 "$PORT_INFO_FILE"
    fi
    
    # 确保日志文件存在
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
}

# 更新 Xray GeoIP 和 GeoSite 数据
update_geodata() {
    echo
    echo -e "$yellow 更新 Xray GeoIP 和 GeoSite 数据 $none"
    echo "----------------------------------------------------------------"
    log_info "开始更新 GeoIP 和 GeoSite 数据"
    
    # 使用官方脚本更新
    if bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata; then
        echo
        echo -e "$green 数据库更新成功! $none"
        log_info "数据库更新成功 (官方脚本)"
        
        # 重启 Xray 服务
        echo
        echo -e "$yellow 重启 Xray 服务... $none"
        if systemctl restart xray; then
            echo -e "$green Xray 服务重启成功! $none"
            log_info "Xray 服务重启成功"
        else
            echo -e "$red Xray 服务重启失败，请手动检查! $none"
            log_error "Xray 服务重启失败"
        fi
    else
        echo -e "$red 数据库更新失败! $none"
        log_error "数据库更新失败 (官方脚本)"
        
        echo
        echo -e "$yellow 尝试手动更新... $none"
        
        # 手动下载更新
        if wget -O /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat && \
           wget -O /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat; then
            echo -e "$green 数据库手动更新成功! $none"
            log_info "数据库手动更新成功"
            
            # 重启 Xray 服务
            echo
            echo -e "$yellow 重启 Xray 服务... $none"
            if systemctl restart xray; then
                echo -e "$green Xray 服务重启成功! $none"
                log_info "Xray 服务重启成功"
            else
                echo -e "$red Xray 服务重启失败，请手动检查! $none"
                log_error "Xray 服务重启失败"
            fi
        else
            echo -e "$red 数据库手动更新失败! $none"
            log_error "数据库手动更新失败"
        fi
    fi
    
    # 显示当前 Xray 版本信息
    echo
    echo -e "$yellow 当前 Xray 版本信息: $none"
    xray --version
    log_info "当前 Xray 版本: $(xray --version | head -n1)"
    echo
    pause
}

# 检查是否安装了必要的依赖
check_dependencies() {
    local dependencies=("curl" "jq" "qrencode" "lsof" "wget" "systemctl")
    local missing=()

    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${yellow}正在安装缺少的依赖: ${missing[*]}${none}"
        apt update -y
        apt install -y "${missing[@]}"
        
        # 再次检查是否成功安装
        for dep in "${missing[@]}"; do
            if ! command -v "$dep" &> /dev/null; then
                echo -e "${red}安装 $dep 失败，请手动安装${none}"
                return 1
            fi
        done
    fi
    
    return 0
}

# 修改 save_port_info() 函数使默认用户也使用随机邮箱
save_port_info() {
    local port=$1
    local uuid=$2
    local private_key=$3
    local public_key=$4
    local shortid=$5
    local domain=$6
    
    # 检查参数是否为空
    if [[ -z "$port" || -z "$uuid" || -z "$private_key" || -z "$public_key" || -z "$shortid" || -z "$domain" ]]; then
        log_error "保存端口配置失败: 参数不完整"
        return 1
    fi

    # 生成随机邮箱
    local random_suffix=$(date +%s%N | md5sum | head -c 8)
    local default_email="user_${random_suffix}@example.com"

    # 检查端口是否已存在，如果存在则更新配置
    if jq -e ".ports[] | select(.port == $port)" "$PORT_INFO_FILE" > /dev/null; then
        # 更新已存在的端口配置
        jq "(.ports[] | select(.port == $port)) |= {
            \"port\": $port,
            \"uuid\": \"$uuid\",
            \"private_key\": \"$private_key\",
            \"public_key\": \"$public_key\",
            \"shortid\": \"$shortid\",
            \"domain\": \"$domain\",
            \"socks5\": (.socks5 // null),
            \"users\": (.users // [{\"uuid\": \"$uuid\", \"email\": \"$default_email\"}])
        }" "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
    else
        # 添加新的端口配置
        jq ".ports += [{
            \"port\": $port,
            \"uuid\": \"$uuid\",
            \"private_key\": \"$private_key\",
            \"public_key\": \"$public_key\",
            \"shortid\": \"$shortid\",
            \"domain\": \"$domain\",
            \"socks5\": null,
            \"users\": [{\"uuid\": \"$uuid\", \"email\": \"$default_email\"}]
        }]" "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
    fi
    
    # 验证更新后的JSON是否有效
    if jq -e . "${PORT_INFO_FILE}.tmp" > /dev/null; then
        mv "${PORT_INFO_FILE}.tmp" "$PORT_INFO_FILE"
        chmod 600 "$PORT_INFO_FILE"
        log_info "保存端口 $port 配置成功"
        return 0
    else
        rm -f "${PORT_INFO_FILE}.tmp"
        log_error "保存端口 $port 配置失败: 无效的JSON"
        return 1
    fi
}

# 设置端口的SOCKS5代理配置
set_port_socks5_config() {
    local port=$1
    local enabled=$2
    local socks5_address=$3
    local socks5_port=$4
    local auth_needed=$5
    local socks5_user=$6
    local socks5_pass=$7
    local udp_over_tcp=$8
    
    # 检查端口是否存在
    if ! jq -e ".ports[] | select(.port == $port)" "$PORT_INFO_FILE" > /dev/null; then
        log_error "设置SOCKS5配置失败: 端口 $port 不存在"
        return 1
    fi

    # 创建SOCKS5配置对象
    local socks5_config
    if [[ "$enabled" == "y" ]]; then
        socks5_config="{
            \"enabled\": true,
            \"address\": \"$socks5_address\",
            \"port\": $socks5_port,
            \"auth_needed\": $([[ "$auth_needed" == "y" ]] && echo "true" || echo "false"),
            \"username\": \"$socks5_user\",
            \"password\": \"$socks5_pass\",
            \"udp_over_tcp\": $([[ "$udp_over_tcp" == "y" ]] && echo "true" || echo "false")
        }"
    else
        socks5_config="null"
    fi
    
    # 更新端口的SOCKS5配置
    jq "(.ports[] | select(.port == $port)) |= (.socks5 = $socks5_config)" "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
    
    # 验证更新后的JSON是否有效
    if jq -e . "${PORT_INFO_FILE}.tmp" > /dev/null; then
        mv "${PORT_INFO_FILE}.tmp" "$PORT_INFO_FILE"
        chmod 600 "$PORT_INFO_FILE"
        log_info "设置端口 $port 的SOCKS5代理配置: 启用=$enabled"
        return 0
    else
        rm -f "${PORT_INFO_FILE}.tmp"
        log_error "设置端口 $port 的SOCKS5代理配置失败: 无效的JSON"
        return 1
    fi
}

# 获取特定端口的配置信息
get_port_info() {
    local port=$1
    
    if [[ -z "$port" ]]; then
        log_error "获取端口信息失败: 端口参数为空"
        return 1
    fi
    
    local info=$(jq -c ".ports[] | select(.port == $port)" "$PORT_INFO_FILE")
    if [[ -z "$info" ]]; then
        log_error "获取端口信息失败: 端口 $port 不存在"
        return 1
    fi
    
    echo "$info"
    return 0
}

# 检查端口是否已配置
check_port_exists() {
    local port=$1
    if jq -e ".ports[] | select(.port == $port)" "$PORT_INFO_FILE" > /dev/null; then
        return 0  # 端口已存在
    fi
    return 1  # 端口不存在
}

# 删除特定端口的配置信息
delete_port_info() {
    local port=$1
    
    # 检查端口是否存在
    if ! check_port_exists "$port"; then
        log_error "删除端口配置失败: 端口 $port 不存在"
        return 1
    fi
    
    # 备份原配置
    cp "$PORT_INFO_FILE" "${PORT_INFO_FILE}.bak"
    
    jq "del(.ports[] | select(.port == $port))" "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
    
    # 验证更新后的JSON是否有效
    if jq -e . "${PORT_INFO_FILE}.tmp" > /dev/null; then
        mv "${PORT_INFO_FILE}.tmp" "$PORT_INFO_FILE"
        chmod 600 "$PORT_INFO_FILE"
        log_info "删除端口 $port 配置成功"
        return 0
    else
        rm -f "${PORT_INFO_FILE}.tmp"
        log_error "删除端口 $port 配置失败: 无效的JSON"
        # 恢复备份
        mv "${PORT_INFO_FILE}.bak" "$PORT_INFO_FILE"
        return 1
    fi
}

# 更新Xray配置文件
update_config_file() {
    # 备份当前配置
    if [[ -f "$CONFIG_FILE" ]]; then
        cp "$CONFIG_FILE" "${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
        # 创建一个完整备份，用于在更新失败时恢复
        cp "$CONFIG_FILE" "${CONFIG_FILE}.full.bak"
    fi
    
# 创建基本配置
cat > "$CONFIG_FILE" << EOL
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "dns": {
  "servers": [
    "8.8.8.8",
    "8.8.4.4",
    "localhost"
  ],
  "queryStrategy": "UseIPv4",
  "tag": "dns-out"
},
  "inbounds": [],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "dns",
      "tag": "dns-out"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOL
    
    # 读取所有端口配置
    local ports_config=$(jq -c '.ports[]' "$PORT_INFO_FILE")
    
    # 临时文件
    local temp_config=$(mktemp)
    cp "$CONFIG_FILE" "$temp_config"
    
    # 创建一个数组存储所有端口配置
    local ports_array=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && ports_array+=("$line")
    done <<< "$ports_config"
    
    log_info "共找到 ${#ports_array[@]} 个端口配置"
    
    # 如果没有找到任何端口配置，返回错误
    if [[ ${#ports_array[@]} -eq 0 ]]; then
        log_error "未找到任何端口配置，配置更新失败"
        return 1
    fi
    
    # 添加每个端口的入站配置 - 使用数组而不是管道
    for port_info in "${ports_array[@]}"; do
        if [[ -z "$port_info" ]]; then
            log_error "端口配置为空，跳过"
            continue
        fi
        
        # 提取信息
        local port=$(echo "$port_info" | jq -r '.port')
        local uuid=$(echo "$port_info" | jq -r '.uuid')
        local private_key=$(echo "$port_info" | jq -r '.private_key')
        local shortid=$(echo "$port_info" | jq -r '.shortid')
        local domain=$(echo "$port_info" | jq -r '.domain')
        
        # 检查关键数据
        if [[ -z "$port" || -z "$uuid" || -z "$private_key" || -z "$shortid" || -z "$domain" ]]; then
            log_error "端口配置数据不完整: port=$port, uuid=$uuid, private_key=$private_key, shortid=$shortid, domain=$domain"
            continue
        fi
        
        # 处理 clients 数组
        local users_exist=$(echo "$port_info" | jq 'has("users")')
        if [[ "$users_exist" != "true" && -n "$uuid" ]]; then
            # 生成随机邮箱
            local random_suffix=$(date +%s%N | md5sum | head -c 8)
            local default_email="user_${random_suffix}@example.com"

            # 如果没有 users 数组但有 uuid，创建一个包含 uuid 的用户
            port_info=$(echo "$port_info" | jq '. + {users: [{uuid: .uuid, email: "'"$default_email"'"}]}')
            log_info "为端口 $port 创建默认用户数组"
        fi
        
        # 生成 clients 数组，确保 email 字段不会破坏 JSON 格式
        local clients_json=$(echo "$port_info" | jq -c 'if has("users") and (.users | length > 0) then 
            [.users[] | {
                id: .uuid, 
                flow: "xtls-rprx-vision", 
                email: (.email | gsub("[^a-zA-Z0-9@._-]"; "") // "user@example.com")
            }] 
        else 
            [{id: .uuid, flow: "xtls-rprx-vision"}] 
        end')

        # 确保生成的 JSON 不为空且格式正确
        if [[ "$clients_json" == "null" || "$clients_json" == "[]" ]]; then
            log_error "端口 $port 的客户端配置为空，使用 UUID 创建默认客户端"
            clients_json="[{\"id\": \"$uuid\", \"flow\": \"xtls-rprx-vision\"}]"
        fi

        # 额外检查生成的 clients_json 是否为有效的 JSON
        if ! echo "$clients_json" | jq -e . >/dev/null 2>&1; then
            log_error "生成的客户端JSON无效: $clients_json"
            # 回退到使用端口的主 UUID
            clients_json="[{\"id\": \"$uuid\", \"flow\": \"xtls-rprx-vision\"}]"
        fi
        
# 创建入站配置
cat > "$temp_config.inbound" << EOL
{
  "listen": "0.0.0.0",
  "port": ${port},
  "protocol": "vless",
  "settings": {
    "clients": ${clients_json},
    "decryption": "none"
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "show": false,
      "dest": "${domain}:443",
      "xver": 0,
      "serverNames": ["${domain}"],
      "privateKey": "${private_key}",
      "shortIds": ["${shortid}"]
    }
  },
  "sniffing": {
    "enabled": true,
    "destOverride": ["http", "tls", "quic"]
  },
  "tag": "inbound-${port}"
}
EOL

        # 验证生成的入站配置是否有效
        if ! jq -e . "$temp_config.inbound" > /dev/null 2>&1; then
            log_error "端口 $port 生成的JSON配置无效"
            echo "无效的入站配置:" >> "$LOG_FILE"
            cat "$temp_config.inbound" >> "$LOG_FILE"  # 将无效配置写入日志文件以便调试
            
            # 记录当前使用的参数以便诊断
            echo "clients_json = $clients_json" >> "$LOG_FILE"
            echo "uuid = $uuid" >> "$LOG_FILE"
            echo "private_key = $private_key" >> "$LOG_FILE"
            echo "domain = $domain" >> "$LOG_FILE"
            echo "shortid = $shortid" >> "$LOG_FILE"
            
            # 尝试修复JSON格式问题
            clients_json=$(echo "$clients_json" | sed 's/\\"/"/g' | sed 's/"/\\"/g')
            
            # 2. 重新生成入站配置
            cat > "$temp_config.inbound" << EOL
{
  "listen": "0.0.0.0",
  "port": ${port},
  "protocol": "vless",
  "settings": {
    "clients": ${clients_json},
    "decryption": "none"
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "show": false,
      "dest": "${domain}:443",
      "xver": 0,
      "serverNames": ["${domain}"],
      "privateKey": "${private_key}",
      "shortIds": ["${shortid}"]
    }
  },
  "sniffing": {
    "enabled": true,
    "destOverride": ["http", "tls", "quic"]
  },
  "tag": "inbound-${port}"
}
EOL
            
            # 再次检查修复后的配置
            if ! jq -e . "$temp_config.inbound" > /dev/null 2>&1; then
                log_error "修复后的配置仍然无效，跳过端口 $port"
                log_error "请考虑删除该端口配置并重新添加"
                continue
            fi
            
            log_info "端口 $port 的配置已修复"
        fi

        # 添加入站配置到主配置
        jq ".inbounds += [$(cat "$temp_config.inbound")]" "$temp_config" > "$temp_config.new"
        if [[ $? -ne 0 ]]; then
            log_error "添加入站配置失败: port=$port"
            continue
        fi
        mv "$temp_config.new" "$temp_config"
        
        # 处理SOCKS5代理配置
        local socks5_config=$(echo "$port_info" | jq -r '.socks5')
        
        if [[ "$socks5_config" != "null" && "$(echo "$socks5_config" | jq -r '.enabled // false')" == "true" ]]; then
            local socks5_address=$(echo "$socks5_config" | jq -r '.address')
            local socks5_port=$(echo "$socks5_config" | jq -r '.port')
            local auth_needed=$(echo "$socks5_config" | jq -r '.auth_needed')
            local socks5_user=$(echo "$socks5_config" | jq -r '.username')
            local socks5_pass=$(echo "$socks5_config" | jq -r '.password')
            local udp_over_tcp=$(echo "$socks5_config" | jq -r '.udp_over_tcp')
            local socks5_tag="socks5-out-$port"
            
            # 创建SOCKS5出站配置
            cat > "$temp_config.socks5" << EOL
{
  "protocol": "socks",
  "settings": {
    "servers": [
      {
        "address": "${socks5_address}",
        "port": ${socks5_port}
EOL

            if [[ "$auth_needed" == "true" ]]; then
                cat >> "$temp_config.socks5" << EOL
        ,"users": [{"user": "${socks5_user}","pass": "${socks5_pass}"}]
EOL
            fi
            
            cat >> "$temp_config.socks5" << EOL
      }
    ]
  }
EOL

            if [[ "$udp_over_tcp" == "true" ]]; then
                cat >> "$temp_config.socks5" << EOL
  ,"streamSettings": {"sockopt": {"udpFragmentSize": 1400,"tcpFastOpen": true,"tcpKeepAliveInterval": 15,"mark": 255}},"transportLayer": true
EOL
            else
                cat >> "$temp_config.socks5" << EOL
  ,"streamSettings": {"sockopt": {"tcpFastOpen": true,"tcpKeepAliveInterval": 15,"mark": 255}}
EOL
            fi
            
            cat >> "$temp_config.socks5" << EOL
  ,"tag": "${socks5_tag}"
}
EOL

            # 验证生成的SOCKS5出站配置是否有效
            if ! jq -e . "$temp_config.socks5" > /dev/null 2>&1; then
                log_error "端口 $port 的SOCKS5出站配置无效，跳过"
                continue
            fi

            # 添加SOCKS5出站到主配置
            jq ".outbounds += [$(cat "$temp_config.socks5")]" "$temp_config" > "$temp_config.new"
            if [[ $? -ne 0 ]]; then
                log_error "添加SOCKS5出站配置失败: port=$port"
                continue
            fi
            mv "$temp_config.new" "$temp_config"
            
            # 创建路由规则
            local network_type=$(if [[ "$udp_over_tcp" == "true" ]]; then echo "tcp,udp"; else echo "tcp"; fi)
            cat > "$temp_config.rule" << EOL
{
  "type": "field",
  "inboundTag": ["inbound-${port}"],
  "outboundTag": "${socks5_tag}"
}
EOL
            
            # 添加DNS路由规则
            cat > "$temp_config.dns_rule" << EOL
{
  "type": "field",
  "inboundTag": ["inbound-${port}"],
  "port": 53,
  "outboundTag": "dns-out"
}
EOL
            
            # 添加DNS路由规则
            jq ".routing.rules += [$(cat "$temp_config.dns_rule")]" "$temp_config" > "$temp_config.new"
            mv "$temp_config.new" "$temp_config"
            
            # 添加路由规则
            jq ".routing.rules += [$(cat "$temp_config.rule")]" "$temp_config" > "$temp_config.new"
            mv "$temp_config.new" "$temp_config"
        fi
    done
    
    # 验证最终配置
    if ! jq -e . "$temp_config" > /dev/null 2>&1; then
        log_error "生成的最终配置无效"
        cat "$temp_config" >> "$LOG_FILE"
        rm -f "$temp_config" "$temp_config.inbound" "$temp_config.socks5" "$temp_config.rule" "$temp_config.dns_rule" "$temp_config.new" 2>/dev/null
        
        # 恢复完整备份
        if [[ -f "${CONFIG_FILE}.full.bak" ]]; then
            log_info "恢复完整备份配置"
            cp "${CONFIG_FILE}.full.bak" "$CONFIG_FILE"
            chmod 644 "$CONFIG_FILE"
        fi
        
        return 1
    fi
    
    # 检查是否至少有一个入站配置
    local inbound_count=$(jq '.inbounds | length' "$temp_config")
    if [[ "$inbound_count" -eq 0 ]]; then
        log_error "更新后的配置没有任何入站配置，更新失败"
        
        # 恢复完整备份
        if [[ -f "${CONFIG_FILE}.full.bak" ]]; then
            log_info "恢复完整备份配置"
            cp "${CONFIG_FILE}.full.bak" "$CONFIG_FILE"
            chmod 644 "$CONFIG_FILE"
        fi
        
        rm -f "$temp_config" "$temp_config.inbound" "$temp_config.socks5" "$temp_config.rule" "$temp_config.dns_rule" "$temp_config.new" 2>/dev/null
        return 1
    fi
    
    # 应用新配置
    cp "$temp_config" "$CONFIG_FILE"
    chmod 644 "$CONFIG_FILE"
    
    # 记录配置更新后的入站数量
    log_info "配置更新完成，共添加 $inbound_count 个入站配置"
    
    # 清理临时文件
    rm -f "$temp_config" "$temp_config.inbound" "$temp_config.socks5" "$temp_config.rule" "$temp_config.dns_rule" "$temp_config.new" "${CONFIG_FILE}.full.bak" 2>/dev/null

    log_info "配置文件已更新"
    return 0
}

# 检查Xray服务状态
check_xray_service() {
    if ! systemctl is-active --quiet xray; then
        echo -e "${red}Xray 服务未运行，尝试启动...${none}"
        systemctl start xray
        sleep 2
        
        if ! systemctl is-active --quiet xray; then
            echo -e "${red}Xray 服务启动失败${none}"
            log_error "Xray服务启动失败"
            return 1
        fi
    fi
    
    echo -e "${green}Xray 服务运行中${none}"
    log_info "Xray服务运行中"
    return 0
}

# 显示所有端口配置
list_port_configurations() {
    echo
    echo -e "$yellow 当前所有端口配置 $none"
    echo "----------------------------------------------------------------"
    
    if [[ ! -s "$PORT_INFO_FILE" ]] || [[ $(jq '.ports | length' "$PORT_INFO_FILE") -eq 0 ]]; then
        echo -e "$red 目前没有配置任何端口，请先添加端口配置 $none"
        return
    fi
    
    echo -e "${cyan}序号   端口    UUID    域名    代理状态${none}"
    echo "----------------------------------------------------------------"
    
    local index=1
    jq -c '.ports[]' "$PORT_INFO_FILE" | while read -r port_info; do
        local port=$(echo "$port_info" | jq -r '.port')
        local uuid=$(echo "$port_info" | jq -r '.uuid')
        # 截取UUID的开头和结尾部分，中间用省略号
        local uuid_short="${uuid:0:8}...${uuid:24}"
        local domain=$(echo "$port_info" | jq -r '.domain')
        local socks5_enabled=$(echo "$port_info" | jq -r '.socks5.enabled // false')
        
        if [[ "$socks5_enabled" == "true" ]]; then
            local socks5_address=$(echo "$port_info" | jq -r '.socks5.address')
            local socks5_port=$(echo "$port_info" | jq -r '.socks5.port')
            socks5_status="${green}启用 (${socks5_address}:${socks5_port})${none}"
        else
            socks5_status="${red}禁用${none}"
        fi
        
        echo -e "${green}$index${none}    ${cyan}$port${none}    ${yellow}$uuid_short${none}    ${magenta}$domain${none}    ${socks5_status}"
        index=$((index+1))
    done
    
    echo "----------------------------------------------------------------"
}

# 备份当前所有配置
backup_configuration() {
    echo
    echo -e "$yellow 备份当前配置 $none"
    echo "----------------------------------------------------------------"
    
    local backup_dir="$HOME/xray_backup_$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"
    
    # 备份端口配置信息
    if [[ -f "$PORT_INFO_FILE" ]]; then
        cp "$PORT_INFO_FILE" "$backup_dir/"
    fi
    
    # 备份Xray配置
    if [[ -f "$CONFIG_FILE" ]]; then
        cp "$CONFIG_FILE" "$backup_dir/"
    fi
    
    # 备份其他配置文件
    cp -r /usr/local/etc/xray/* "$backup_dir/" 2>/dev/null
    
    echo -e "${green}配置已备份至: $backup_dir${none}"
    log_info "备份配置到 $backup_dir"
    
    # 创建一个压缩包
    tar -czf "${backup_dir}.tar.gz" -C "$(dirname "$backup_dir")" "$(basename "$backup_dir")"
    rm -rf "$backup_dir"
    
    echo -e "${green}备份文件: ${backup_dir}.tar.gz${none}"
    echo -e "使用以下命令恢复: tar -xzf ${backup_dir}.tar.gz -C /"
    
    pause
}

# 恢复配置
restore_configuration() {
    echo
    echo -e "$yellow 恢复配置 $none"
    echo "----------------------------------------------------------------"
    
    echo -e "请输入备份文件路径:"
    read -p "$(echo -e "(例如: ${HOME}/xray_backup_20220101000000.tar.gz): ")" backup_file
    
    if [[ ! -f "$backup_file" ]]; then
        echo -e "${red}备份文件不存在${none}"
        return
    fi
    
    echo -e "${yellow}警告: 恢复将覆盖当前配置，是否继续?${none}"
    read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" confirm
    
    if [[ "$confirm" != "y" ]]; then
        echo -e "${yellow}操作已取消${none}"
        return
    fi
    
    # 创建临时目录
    local temp_dir=$(mktemp -d)
    
    # 解压备份文件
    tar -xzf "$backup_file" -C "$temp_dir"
    
    # 恢复端口配置信息
    if [[ -f "$temp_dir/$(basename "$PORT_INFO_FILE")" ]]; then
        cp "$temp_dir/$(basename "$PORT_INFO_FILE")" "$PORT_INFO_FILE"
        chmod 600 "$PORT_INFO_FILE"
    fi
    
    # 恢复Xray配置
    if [[ -f "$temp_dir/$(basename "$CONFIG_FILE")" ]]; then
        if ! cp "$temp_dir/$(basename "$CONFIG_FILE")" "$CONFIG_FILE"; then
            echo -e "${red}复制配置文件失败${none}"
            log_error "恢复配置文件失败"
            rm -rf "$temp_dir"
            return 1
        fi
        chmod 644 "$CONFIG_FILE"
    fi
    
    # 重启Xray服务
    echo -e "$yellow 重启 Xray 服务... $none"
    if systemctl restart xray; then
        echo -e "$green Xray 服务重启成功! $none"
        log_info "恢复配置后重启Xray成功"
    else
        echo -e "$red Xray 服务重启失败，请手动检查! $none"
        log_error "恢复配置后重启Xray失败"
    fi
    
    # 删除临时目录
    rm -rf "$temp_dir"
    
    echo -e "${green}配置恢复成功${none}"
    log_info "配置恢复成功"
    
    pause
}

# 添加新端口配置
add_port_configuration() {
    echo
    echo -e "$yellow 添加新端口配置 $none"
    echo "----------------------------------------------------------------"
    
     # 检查是否安装了Xray
    if ! command -v xray &> /dev/null; then
        echo -e "${red}未检测到Xray安装，无法添加端口配置${none}"
        echo -e "是否现在安装Xray? [y/N]"
        read -r install_xray_now
        if [[ $install_xray_now =~ ^[Yy]$ ]]; then
            install_xray
        else
            echo -e "${yellow}已取消添加端口配置，请先安装Xray${none}"
            return
        fi
    fi

    # 获取本机IP
    if ! get_local_ips; then
        echo -e "${red}获取IP地址失败!${none}"
        echo -e "是否继续安装?[y/N]"
        read -r continue_install
        if [[ ! $continue_install =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    
    # 网络栈选择
    echo
    echo -e "如果你的服务器是${magenta}双栈(同时有IPv4和IPv6的IP)${none}，请选择你要使用的IP类型"
    echo "如果你不懂这段话是什么意思, 请直接回车"
    read -p "$(echo -e "输入 ${cyan}4${none} 表示IPv4, ${cyan}6${none} 表示IPv6: ") " netstack
    
    if [[ $netstack = "4" ]]; then
        ip=${IPv4}
    elif [[ $netstack = "6" ]]; then
        ip=${IPv6}
    else
        if [[ -n "$IPv4" ]]; then
            ip=${IPv4}
            netstack=4
        elif [[ -n "$IPv6" ]]; then
            ip=${IPv6}
            netstack=6
        else
            warn "没有获取到公共IP"
        fi
    fi
    
    # 端口选择
    while :; do
    read -p "$(echo -e "请输入端口 [${magenta}1-65535${none}]，建议使用大于1024的端口（默认: ${cyan}7999${none}）: ")" port
    if [[ -z "$port" ]]; then
        port=7999
    fi
    
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        error
        continue
    fi
        
        # 检查端口是否已被配置
        if check_port_exists "$port"; then
            echo -e "${red}端口 $port 已被配置，请选择其他端口${none}"
            continue
        fi
        
        # 检查端口是否被占用
        if lsof -i:"$port" >/dev/null 2>&1; then
            echo -e "${red}端口 $port 已被其他程序占用，请选择其他端口${none}"
            continue
        fi
        
        echo
        echo -e "$yellow 端口 (Port) = ${cyan}${port}${none}"
        echo "----------------------------------------------------------------"
        break
    done
    
    # 生成UUID
    uuidSeed=${ip}$(cat /proc/sys/kernel/hostname)$(cat /etc/timezone)${port}$(date +%s%N)
    default_uuid=$(curl -sL https://www.uuidtools.com/api/generate/v3/namespace/ns:dns/name/${uuidSeed} | grep -oP '[^-]{8}-[^-]{4}-[^-]{4}-[^-]{4}-[^-]{12}')
    
    while :; do
        echo -e "请输入 "${yellow}"UUID"${none}" "
        read -p "$(echo -e "(默认ID: ${cyan}${default_uuid}${none}): ")" uuid
        [ -z "$uuid" ] && uuid=$default_uuid
        
        if [[ ! "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
            error
            continue
        fi
        
        echo
        echo -e "$yellow UUID = ${cyan}$uuid${none}"
        echo "----------------------------------------------------------------"
        break
    done
    
    # 生成密钥
    private_key=$(echo -n ${uuid} | md5sum | head -c 32 | base64 -w 0 | tr '+/' '-_' | tr -d '=')
    tmp_key=$(echo -n ${private_key} | xargs xray x25519 -i)
    default_private_key=$(echo ${tmp_key} | awk '{print $3}')
    default_public_key=$(echo ${tmp_key} | awk '{print $6}')
    
    echo -e "请输入 "$yellow"x25519 Private Key"$none" x25519私钥 :"
    read -p "$(echo -e "(默认私钥 Private Key: ${cyan}${default_private_key}${none}): ")" private_key
    if [[ -z "$private_key" ]]; then 
        private_key=$default_private_key
        public_key=$default_public_key
    else
        tmp_key=$(echo -n ${private_key} | xargs xray x25519 -i)
        private_key=$(echo ${tmp_key} | awk '{print $3}')
        public_key=$(echo ${tmp_key} | awk '{print $6}')
    fi
    
    echo
    echo -e "$yellow 私钥 (PrivateKey) = ${cyan}${private_key}${none}"
    echo -e "$yellow 公钥 (PublicKey) = ${cyan}${public_key}${none}"
    echo "----------------------------------------------------------------"
    
    # ShortID
    default_shortid=$(echo -n ${uuid} | sha1sum | head -c 16)
    while :; do
        echo -e "请输入 "$yellow"ShortID"$none" :"
        read -p "$(echo -e "(默认ShortID: ${cyan}${default_shortid}${none}): ")" shortid
        [ -z "$shortid" ] && shortid=$default_shortid
        
        if [[ ${#shortid} -gt 16 ]]; then
            error
            continue
        elif [[ $(( ${#shortid} % 2 )) -ne 0 ]]; then
            error
            continue
        fi
        
        echo
        echo -e "$yellow ShortID = ${cyan}${shortid}${none}"
        echo "----------------------------------------------------------------"
        break
    done
    
    # 目标网站
    echo -e "请输入一个 ${magenta}合适的域名${none} 作为 SNI"
    read -p "$(echo -e "(例如: learn.microsoft.com): ")" domain
    [ -z "$domain" ] && domain="learn.microsoft.com"
    
    echo
    echo -e "$yellow SNI = ${cyan}$domain${none}"
    echo "----------------------------------------------------------------"
    
    # 保存基本端口配置
    if ! save_port_info "$port" "$uuid" "$private_key" "$public_key" "$shortid" "$domain"; then
        echo -e "${red}保存配置失败，请重试${none}"
        return 1
    fi
    
    # SOCKS5 代理设置
    echo
    echo -e "$yellow 是否为此端口配置 SOCKS5 转发代理? $none"
    read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" socks5_enabled
    [ -z "$socks5_enabled" ] && socks5_enabled="n"
    
    if [[ $socks5_enabled = "y" ]]; then
        configure_socks5_for_port "$port"
    fi
    
    # 更新配置文件
    echo -e "${yellow}正在更新配置文件...${none}"
    if ! update_config_file; then
        echo -e "${red}更新配置文件失败，请检查日志${none}"
        return 1
    fi
    
    # 重启 Xray
    echo
    echo -e "$yellow 重启 Xray 服务... $none"
    if systemctl restart xray; then
        echo -e "$green Xray 服务重启成功! $none"
        log_info "添加端口 $port 后重启 Xray 成功"
    else
        echo -e "$red Xray 服务重启失败，请手动检查! $none"
        log_error "添加端口 $port 后重启 Xray 失败"
        systemctl status xray
        return 1
    fi
    
    # 生成连接信息
    generate_connection_info "$port" "$uuid" "$public_key" "$shortid" "$domain" "$ip" "$netstack"
    
    echo
    echo -e "$green 端口配置成功添加! $none"
    log_info "端口 $port 配置成功添加"
    pause
}

# 为指定端口配置SOCKS5代理
configure_socks5_for_port() {
    local port=$1
    
    # SOCKS5 服务器地址
    read -p "$(echo -e "请输入 SOCKS5 服务器地址: ")" socks5_address
    if [ -z "$socks5_address" ]; then
        error
        return 1
    fi
    
    # SOCKS5 端口
    read -p "$(echo -e "请输入 SOCKS5 端口: ")" socks5_port
    if [ -z "$socks5_port" ] || ! [[ "$socks5_port" =~ ^[0-9]+$ ]] || [[ "$socks5_port" -lt 1 ]] || [[ "$socks5_port" -gt 65535 ]]; then
        error
        return 1
    fi
    
    # 是否需要认证
    echo -e "是否需要用户名密码认证?"
    read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" auth_needed
    [ -z "$auth_needed" ] && auth_needed="n"
    
    socks5_user=""
    socks5_pass=""
    if [[ $auth_needed = "y" ]]; then
        read -p "$(echo -e "请输入用户名: ")" socks5_user
        read -p "$(echo -e "请输入密码: ")" socks5_pass
        echo  # 为了换行
    fi
    
    # 是否启用 UDP over TCP
    echo -e "是否启用 UDP over TCP?"
    read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" udp_over_tcp
    [ -z "$udp_over_tcp" ] && udp_over_tcp="n"
    
    if [[ $udp_over_tcp = "n" ]]; then
        echo -e "$yellow 注意：未启用 UDP over TCP，仅进行 TCP 转发 $none"
    fi
    
    # 设置SOCKS5代理配置
    if ! set_port_socks5_config "$port" "y" "$socks5_address" "$socks5_port" "$auth_needed" "$socks5_user" "$socks5_pass" "$udp_over_tcp"; then
        echo -e "${red}SOCKS5 代理配置失败${none}"
        return 1
    fi
    
    echo -e "${green}SOCKS5 代理配置成功添加到端口 $port${none}"
    log_info "为端口 $port 配置 SOCKS5 代理"
    return 0
}

# 生成单个端口的连接信息
generate_connection_info() {
    local port=$1
    local uuid=$2
    local public_key=$3
    local shortid=$4
    local domain=$5
    local ip=$6
    local netstack=$7
    
    echo
    echo "---------- 端口 $port 的 Xray 配置信息 -------------"
    echo -e "$green ---提示..这是 VLESS Reality 服务器配置--- $none"
    echo -e "$yellow 地址 (Address) = $cyan${ip}$none"
    echo -e "$yellow 端口 (Port) = ${cyan}${port}${none}"
    echo -e "$yellow 用户ID (User ID / UUID) = $cyan${uuid}$none"
    echo -e "$yellow 流控 (Flow) = ${cyan}xtls-rprx-vision${none}"
    echo -e "$yellow 加密 (Encryption) = ${cyan}none${none}"
    echo -e "$yellow 传输协议 (Network) = ${cyan}tcp$none"
    echo -e "$yellow 伪装类型 (header type) = ${cyan}none$none"
    echo -e "$yellow 底层传输安全 (TLS) = ${cyan}reality$none"
    echo -e "$yellow SNI = ${cyan}${domain}$none"
    echo -e "$yellow 指纹 (Fingerprint) = ${cyan}random${none}"
    echo -e "$yellow 公钥 (PublicKey) = ${cyan}${public_key}$none"
    echo -e "$yellow ShortId = ${cyan}${shortid}$none"
    echo -e "$yellow SpiderX = ${cyan}${none}"
    
    # 检查是否配置了SOCKS5代理
    local port_info=$(get_port_info "$port")
    if [[ -n "$port_info" ]]; then
        local socks5_enabled=$(echo "$port_info" | jq -r '.socks5.enabled // false')
        if [[ "$socks5_enabled" == "true" ]]; then
            local socks5_address=$(echo "$port_info" | jq -r '.socks5.address')
            local socks5_port=$(echo "$port_info" | jq -r '.socks5.port')
            echo -e "$yellow SOCKS5代理 = ${cyan}已启用 (${socks5_address}:${socks5_port})$none"
        fi
    fi
    
    # 生成链接
    if [[ $netstack = "6" ]]; then
        ip="[$ip]"
    fi
    
    vless_reality_url="vless://${uuid}@${ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=random&pbk=${public_key}&sid=${shortid}&#VLESS_R_${port}"
    
    echo
    echo "---------- VLESS Reality URL ----------"
    echo -e "${cyan}${vless_reality_url}${none}"
    echo
    
    # 生成二维码
    echo "二维码:"
    qrencode -t UTF8 "$vless_reality_url"
    qrencode -t ANSI "$vless_reality_url"
    
    # 保存信息到文件
    echo "$vless_reality_url" > "$HOME/vless_reality_${port}.txt"
    qrencode -t UTF8 "$vless_reality_url" >> "$HOME/vless_reality_${port}.txt"
    qrencode -t ANSI "$vless_reality_url" >> "$HOME/vless_reality_${port}.txt"
    
    echo
    echo "链接信息已保存到 $HOME/vless_reality_${port}.txt"
    log_info "生成端口 $port 的连接信息，保存到 $HOME/vless_reality_${port}.txt"
}

# 修改端口配置
modify_port_configuration() {
    echo
    echo -e "$yellow 修改端口配置 $none"
    echo "----------------------------------------------------------------"
    
    if [[ ! -s "$PORT_INFO_FILE" ]] || [[ $(jq '.ports | length' "$PORT_INFO_FILE") -eq 0 ]]; then
        echo -e "$red 目前没有配置任何端口，请先添加端口配置 $none"
        return
    fi
    
    # 显示所有端口
    list_port_configurations
    
    # 选择要修改的端口
    local port_count=$(jq '.ports | length' "$PORT_INFO_FILE")
    while :; do
        read -p "$(echo -e "请选择要修改的配置序号 [${green}1-$port_count${none}]: ")" port_index
        
        if [[ -z "$port_index" ]] || ! [[ "$port_index" =~ ^[0-9]+$ ]] || [[ "$port_index" -lt 1 ]] || [[ "$port_index" -gt "$port_count" ]]; then
            error
            continue
        fi
        
        # 获取对应的端口信息
        local selected_port_info=$(jq -c ".ports[$(($port_index-1))]" "$PORT_INFO_FILE")
        local port=$(echo "$selected_port_info" | jq -r '.port')
        
        echo
        echo -e "$yellow 正在修改端口 ${cyan}$port${none} 的配置 $none"
        break
    done
    
    # 修改菜单
    echo "----------------------------------------------------------------"
    echo -e "  ${green}1.${none} 修改UUID"
    echo -e "  ${green}2.${none} 修改域名(SNI)"
    echo -e "  ${green}3.${none} 修改ShortID"
    echo -e "  ${green}4.${none} 修改SOCKS5代理设置"
    echo -e "  ${green}5.${none} 用户管理"
    echo -e "  ${green}6.${none} 返回上一级菜单"
    echo "----------------------------------------------------------------"
    
    read -p "$(echo -e "请选择 [${green}1-6${none}]: ")" modify_choice
    
    case $modify_choice in
        1)
            # 修改UUID
            modify_port_uuid "$port"
            ;;
            
        2)
            # 修改域名
            modify_port_domain "$port"
            ;;
            
        3)
            # 修改ShortID
            modify_port_shortid "$port"
            ;;
            
        4)
            # 修改SOCKS5代理设置
            modify_port_socks5 "$port"
            ;;
            
        5)
            # 用户管理
            manage_port_users "$port"
            ;;
            
        6)
            return
            ;;
            
        *)
            error
            pause
            continue
            ;;
    esac
    
    # 更新配置文件
    echo -e "${yellow}正在更新配置文件...${none}"
    if ! update_config_file; then
        echo -e "${red}更新配置文件失败，请检查日志${none}"
        return 1
    fi
    
    # 重启 Xray
    echo
    echo -e "$yellow 重启 Xray 服务... $none"
    if systemctl restart xray; then
        echo -e "$green Xray 服务重启成功! $none"
        log_info "修改端口 $port 配置后重启 Xray 成功"
    else
        echo -e "$red Xray 服务重启失败，请手动检查! $none"
        log_error "修改端口 $port 配置后重启 Xray 失败"
        systemctl status xray
        return 1
    fi

    
    pause
}

# 用户管理功能
manage_port_users() {
    local port=$1
    
    while true; do
        clear  # 清理屏幕
        
        local port_info=$(get_port_info "$port")
        if [[ $? -ne 0 ]]; then
            log_error "获取端口 $port 信息失败"
            return 1
        fi
        
        echo
        echo -e "$yellow 用户管理 - 端口 $port $none"
        echo "----------------------------------------------------------------"
        
        # 检查是否有用户数组，如果没有则初始化
        if ! echo "$port_info" | jq -e 'has("users")' > /dev/null; then
            # 兼容旧配置，将原UUID转移到users数组中
            local uuid=$(echo "$port_info" | jq -r '.uuid')
            if [[ -n "$uuid" ]]; then
                # 生成随机邮箱
                local random_suffix=$(date +%s%N | md5sum | head -c 8)
                local default_email="user_${random_suffix}@example.com"
                
                # 更新配置到新格式
                port_info=$(echo "$port_info" | jq '. + {users: [{uuid: .uuid, email: "'"$default_email"'"}]}')
                # 将更新后的配置保存
                jq "(.ports[] | select(.port == $port)) |= $port_info" "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
                if jq -e . "${PORT_INFO_FILE}.tmp" > /dev/null; then
                    mv "${PORT_INFO_FILE}.tmp" "$PORT_INFO_FILE"
                    chmod 600 "$PORT_INFO_FILE"
                    log_info "为端口 $port 初始化用户数组"
                else
                    rm -f "${PORT_INFO_FILE}.tmp"
                    log_error "为端口 $port 初始化用户数组失败: 无效的JSON"
                    return 1
                fi
            else
                log_error "端口 $port 没有有效的UUID，无法初始化用户数组"
                echo -e "${red}端口 $port 没有有效的UUID，无法管理用户${none}"
                pause
                return 1
            fi
        fi
        
        # 用户管理菜单
        echo -e "  ${green}1.${none} 查看所有用户"
        echo -e "  ${green}2.${none} 添加新用户"
        echo -e "  ${green}3.${none} 删除用户"
        echo -e "  ${green}4.${none} 修改用户UUID"
        echo -e "  ${green}5.${none} 返回上一级菜单"
        echo "----------------------------------------------------------------"
        
        read -p "$(echo -e "请选择 [${green}1-5${none}]: ")" user_choice
        
        case $user_choice in
            1)
                # 查看所有用户
                list_port_users "$port"
                ;;
                
            2)
                # 添加新用户
                add_port_user "$port"
                ;;
                
            3)
                # 删除用户
                delete_port_user "$port"
                ;;
                
            4)
                # 修改用户UUID
                modify_port_user_uuid "$port"
                ;;
                
            5)
                # 返回上一级菜单 - 直接退出循环
                return 0
                ;;
                
            *)
                error
                pause
                ;;
        esac
    done
}

# 列出端口的所有用户
list_port_users() {
    local port=$1
    local port_info=$(get_port_info "$port")
    
    clear  # 清屏
    echo
    echo -e "$yellow 端口 $port 的所有用户 $none"
    echo "----------------------------------------------------------------"
    
    local users=$(echo "$port_info" | jq -c '.users[]')
    if [[ -z "$users" ]]; then
        echo -e "$red 此端口没有配置任何用户 $none"
        pause
        return  # 直接返回，不再调用 manage_port_users
    fi
    
    echo -e "${cyan}序号   UUID    邮箱${none}"
    echo "----------------------------------------------------------------"
    
    local index=1
    echo "$port_info" | jq -c '.users[]' | while read -r user_info; do
        local uuid=$(echo "$user_info" | jq -r '.uuid')
        local email=$(echo "$user_info" | jq -r '.email')
        # 截取UUID的开头和结尾部分，中间用省略号
        local uuid_short="${uuid:0:8}...${uuid:24}"
        
        echo -e "${green}$index${none}    ${yellow}$uuid_short${none}    ${magenta}$email${none}"
        index=$((index+1))
    done
    
    echo "----------------------------------------------------------------"
    pause
    return  # 直接返回，不再调用 manage_port_users
}

# 添加新用户
add_port_user() {
    local port=$1
    
    log_info "开始为端口 $port 添加新用户"
    
    local port_info=$(get_port_info "$port")
    if [[ $? -ne 0 ]]; then
        log_error "获取端口 $port 信息失败"
        return 1
    fi
    
    echo -e "${yellow}正在处理端口信息...${none}"
    echo "端口信息: $(echo "$port_info" | jq -c .)"
    
    echo
    echo -e "$yellow 添加新用户 - 端口 $port $none"
    echo "----------------------------------------------------------------"
    
    # 检查是否有用户数组，如果没有则初始化
    if ! echo "$port_info" | jq -e 'has("users")' > /dev/null; then
        # 兼容旧配置，将原UUID转移到users数组中
        local uuid=$(echo "$port_info" | jq -r '.uuid // ""')
        if [[ -n "$uuid" ]]; then
            # 更新配置到新格式
            port_info=$(echo "$port_info" | jq '. + {users: [{uuid: .uuid, email: "default@user.com"}]}')
            # 将更新后的配置保存
            jq "(.ports[] | select(.port == $port)) |= $port_info" "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
            if jq -e . "${PORT_INFO_FILE}.tmp" > /dev/null; then
                mv "${PORT_INFO_FILE}.tmp" "$PORT_INFO_FILE"
                chmod 600 "$PORT_INFO_FILE"
                log_info "为端口 $port 初始化用户数组"
                # 重新获取更新后的信息
                port_info=$(get_port_info "$port")
            else
                rm -f "${PORT_INFO_FILE}.tmp"
                log_error "为端口 $port 初始化用户数组失败: 无效的JSON"
                return 1
            fi
        else
            log_error "端口 $port 没有有效的UUID，无法初始化用户数组"
            return 1
        fi
    fi
    
    # 生成随机UUID
    local ip=$([ "$netstack" = "6" ] && echo "$IPv6" || echo "$IPv4")
    local uuidSeed=${ip}$(cat /proc/sys/kernel/hostname)$(cat /etc/timezone)${port}$(date +%s%N)
    local default_uuid=$(curl -sL https://www.uuidtools.com/api/generate/v3/namespace/ns:dns/name/${uuidSeed} | grep -oP '[^-]{8}-[^-]{4}-[^-]{4}-[^-]{4}-[^-]{12}')
    
    # 输入UUID
    while :; do
        echo -e "请输入新用户的 "${yellow}"UUID"${none}" "
        read -p "$(echo -e "(默认ID: ${cyan}${default_uuid}${none}): ")" uuid
        [ -z "$uuid" ] && uuid=$default_uuid
        
        if [[ ! "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
            error
            continue
        fi
        
        # 检查UUID是否已存在
        local uuid_exists=$(echo "$port_info" | jq -r '.users[] | select(.uuid == "'$uuid'") | .uuid')
        if [[ -n "$uuid_exists" ]]; then
            echo -e "${red}UUID已存在，请使用其他UUID${none}"
            continue
        fi
        
        echo
        echo -e "$yellow UUID = ${cyan}$uuid${none}"
        break
    done
    
    # 生成随机邮箱
    local random_suffix=$(date +%s%N | md5sum | head -c 8)
    local default_email="user_${random_suffix}@example.com"
    
    # 输入邮箱
    echo -e "请输入用户邮箱（用于标识，可选）"
    read -p "$(echo -e "(默认: ${cyan}${default_email}${none}): ")" email
    [ -z "$email" ] && email="$default_email"
    
    echo
    echo -e "$yellow 邮箱 = ${cyan}$email${none}"
    
    # 添加新用户
    echo "正在添加新用户..."
    echo "UUID: $uuid"
    echo "Email: $email"

    # 检查UUID是否有效
    if [[ ! "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        log_error "无效的UUID格式: $uuid"
        return 1
    fi

    # 备份当前配置
    cp "$PORT_INFO_FILE" "${PORT_INFO_FILE}.bak"

    # 安全地更新端口配置
    jq_query=".ports[] | select(.port == $port)"
    current_users=$(jq -c "$jq_query | .users // null" "$PORT_INFO_FILE")

    # 过滤邮箱中可能导致JSON解析问题的字符
    email=$(echo "$email" | sed 's/[^a-zA-Z0-9@._-]//g')

    if [[ "$current_users" == "null" || "$current_users" == "" ]]; then
        # 如果users字段不存在或为空，创建新的users数组
        jq "(.ports[] | select(.port == $port)) |= (. + {users: [{uuid: \"$uuid\", email: \"$email\"}]})" "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
    else
        # 向现有users数组添加新用户
        jq "(.ports[] | select(.port == $port)) |= (.users += [{uuid: \"$uuid\", email: \"$email\"}])" "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
    fi

    # 验证更新后的JSON是否有效
    if ! jq -e . "${PORT_INFO_FILE}.tmp" > /dev/null 2>&1; then
        rm -f "${PORT_INFO_FILE}.tmp"
        log_error "生成的配置JSON无效，用户添加失败"
        return 1
    fi

    # 验证更新后的JSON是否有效
    if jq -e . "${PORT_INFO_FILE}.tmp" > /dev/null; then
        mv "${PORT_INFO_FILE}.tmp" "$PORT_INFO_FILE"
        chmod 600 "$PORT_INFO_FILE"
        success "用户添加成功!"
        log_info "为端口 $port 添加新用户 UUID: $uuid, 邮箱: $email"
    else
        rm -f "${PORT_INFO_FILE}.tmp"
        log_error "生成的配置无效，用户添加失败"
        # 恢复备份
        mv "${PORT_INFO_FILE}.bak" "$PORT_INFO_FILE"
        return 1
    fi
    
    # 更新配置文件
    echo "更新配置文件..."
    if ! update_config_file; then
        log_error "配置文件更新失败"
        # 恢复备份
        mv "${PORT_INFO_FILE}.bak" "$PORT_INFO_FILE"
        return 1
    fi

    # 重启服务
    echo "重启Xray服务..."
    if ! systemctl restart xray; then
        log_error "Xray服务重启失败，请手动检查"
        systemctl status xray
        # 恢复备份
        mv "${PORT_INFO_FILE}.bak" "$PORT_INFO_FILE"
        update_config_file
        systemctl restart xray
        return 1
    fi

    log_info "Xray服务已重启"
    
    # 生成连接信息
    local domain=$(echo "$port_info" | jq -r '.domain')
    local public_key=$(echo "$port_info" | jq -r '.public_key')
    local shortid=$(echo "$port_info" | jq -r '.shortid')
    
    # 生成链接
    if [[ $netstack = "6" ]]; then
        ip="[$ip]"
    fi
    
    vless_reality_url="vless://${uuid}@${ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=random&pbk=${public_key}&sid=${shortid}&#VLESS_R_${port}_${email}"
    
    echo
    echo "---------- 新用户的 VLESS Reality URL ----------"
    echo -e "${cyan}${vless_reality_url}${none}"
    echo
    
    # 生成二维码
    echo "二维码:"
    qrencode -t UTF8 "$vless_reality_url"
    
    # 保存信息到文件
    echo "$vless_reality_url" > "$HOME/vless_reality_${port}_${email}.txt"
    echo "链接信息已保存到 $HOME/vless_reality_${port}_${email}.txt"
    
    pause
    return
}

# 删除用户
delete_port_user() {
    local port=$1
    local port_info=$(get_port_info "$port")
    
    echo
    echo -e "$yellow 删除用户 - 端口 $port $none"
    echo "----------------------------------------------------------------"
    
    # 列出所有用户
    local users=$(echo "$port_info" | jq -c '.users[]')
    if [[ -z "$users" ]]; then
        echo -e "$red 此端口没有配置任何用户 $none"
        pause
        manage_port_users "$port"  # 返回用户管理菜单
        return
    fi
    
    echo -e "${cyan}序号   UUID    邮箱${none}"
    echo "----------------------------------------------------------------"
    
    local index=1
    echo "$port_info" | jq -c '.users[]' | while read -r user_info; do
        local uuid=$(echo "$user_info" | jq -r '.uuid')
        local email=$(echo "$user_info" | jq -r '.email')
        # 截取UUID的开头和结尾部分，中间用省略号
        local uuid_short="${uuid:0:8}...${uuid:24}"
        
        echo -e "${green}$index${none}    ${yellow}$uuid_short${none}    ${magenta}$email${none}"
        index=$((index+1))
    done
    
    echo "----------------------------------------------------------------"
    
    # 获取用户数量
    local user_count=$(echo "$port_info" | jq '.users | length')
    
    # 至少保留一个用户
    if [[ $user_count -le 1 ]]; then
        echo -e "${red}至少需要保留一个用户，无法删除${none}"
        pause
        manage_port_users "$port"  # 返回用户管理菜单
        return
    fi
    
    # 选择要删除的用户
    while :; do
        read -p "$(echo -e "请选择要删除的用户序号 [${green}1-$user_count${none}], 输入 0 取消: ")" user_index
        
        if [[ "$user_index" == "0" ]]; then
            echo -e "$yellow 操作已取消 $none"
            manage_port_users "$port"  # 返回用户管理菜单
            return
        fi
        
        if [[ -z "$user_index" ]] || ! [[ "$user_index" =~ ^[0-9]+$ ]] || [[ "$user_index" -lt 1 ]] || [[ "$user_index" -gt "$user_count" ]]; then
            error
            continue
        fi
        
        break
    done
    
    # 获取要删除的用户信息
    local user_to_delete=$(echo "$port_info" | jq -c ".users[$(($user_index-1))]")
    local uuid_to_delete=$(echo "$user_to_delete" | jq -r '.uuid')
    local email_to_delete=$(echo "$user_to_delete" | jq -r '.email')
    
    echo
    echo -e "$yellow 确认要删除以下用户吗? $none"
    echo -e "UUID: ${cyan}$uuid_to_delete${none}"
    echo -e "邮箱: ${cyan}$email_to_delete${none}"
    read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" confirm_delete
    
    if [[ "$confirm_delete" == "y" ]]; then
        # 备份当前配置
        cp "$PORT_INFO_FILE" "${PORT_INFO_FILE}.bak"
        
        # 删除用户
        local updated_port_info=$(echo "$port_info" | jq "del(.users[$(($user_index-1))])")
        
        # 保存更新后的配置
        jq "(.ports[] | select(.port == $port)) |= $updated_port_info" "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
        
        # 验证更新后的JSON是否有效
        if jq -e . "${PORT_INFO_FILE}.tmp" > /dev/null; then
            mv "${PORT_INFO_FILE}.tmp" "$PORT_INFO_FILE"
            chmod 600 "$PORT_INFO_FILE"
            success "用户删除成功!"
            log_info "从端口 $port 删除用户 UUID: $uuid_to_delete, 邮箱: $email_to_delete"
            
            # 删除与此用户相关的连接信息文件
            echo -e "$yellow 删除用户连接信息文件... $none"
            # 处理email可能含有特殊字符的情况
            local sanitized_email=$(echo "$email_to_delete" | sed 's/[^a-zA-Z0-9@._-]/_/g')
            
            # 尝试按照多种可能的模式匹配用户文件
            local user_files_count=0
            
            # 1. 尝试通过端口+email匹配
            if ls $HOME/vless_reality_${port}_${sanitized_email}.txt 1>/dev/null 2>&1; then
                rm -f $HOME/vless_reality_${port}_${sanitized_email}.txt
                user_files_count=$((user_files_count+1))
                log_info "删除了用户文件 vless_reality_${port}_${sanitized_email}.txt"
            fi
            
            # 2. 尝试UUID匹配（更通用的方法）
            for file in $HOME/vless_reality_*.txt; do
                if [[ -f "$file" ]] && grep -q "$uuid_to_delete" "$file"; then
                    rm -f "$file"
                    user_files_count=$((user_files_count+1))
                    log_info "删除了包含UUID的文件 $(basename "$file")"
                fi
            done
            
            if [[ $user_files_count -gt 0 ]]; then
                echo -e "$green 成功删除 $user_files_count 个用户连接信息文件 $none"
            else
                echo -e "$yellow 未找到与此用户相关的连接信息文件 $none"
                log_info "未找到与用户 $email_to_delete ($uuid_to_delete) 相关的连接信息文件"
            fi
            
            # 更新配置文件并重启服务
            if ! update_config_file; then
                log_error "更新配置文件失败，尝试恢复备份"
                mv "${PORT_INFO_FILE}.bak" "$PORT_INFO_FILE"
                update_config_file
                systemctl restart xray
                pause
                manage_port_users "$port"
                return
            fi
            
            if ! systemctl restart xray; then
                log_error "重启Xray服务失败，尝试恢复备份"
                mv "${PORT_INFO_FILE}.bak" "$PORT_INFO_FILE"
                update_config_file
                systemctl restart xray
                pause
                manage_port_users "$port"
                return
            fi
        else
            rm -f "${PORT_INFO_FILE}.tmp"
            log_error "生成的JSON配置无效，用户删除失败"
            # 恢复备份
            mv "${PORT_INFO_FILE}.bak" "$PORT_INFO_FILE"
        fi
    else
        echo -e "$yellow 操作已取消 $none"
    fi
    
    pause
    manage_port_users "$port"  # 返回用户管理菜单
}

# 修改用户UUID
modify_port_user_uuid() {
    local port=$1
    local port_info=$(get_port_info "$port")
    
    echo
    echo -e "$yellow 修改用户UUID - 端口 $port $none"
    echo "----------------------------------------------------------------"
    
    # 列出所有用户
    local users=$(echo "$port_info" | jq -c '.users[]')
    if [[ -z "$users" ]]; then
        echo -e "$red 此端口没有配置任何用户 $none"
        pause
        manage_port_users "$port"  # 返回用户管理菜单
        return
    fi
    
    echo -e "${cyan}序号   UUID    邮箱${none}"
    echo "----------------------------------------------------------------"
    
    local index=1
    echo "$port_info" | jq -c '.users[]' | while read -r user_info; do
        local uuid=$(echo "$user_info" | jq -r '.uuid')
        local email=$(echo "$user_info" | jq -r '.email')
        # 截取UUID的开头和结尾部分，中间用省略号
        local uuid_short="${uuid:0:8}...${uuid:24}"
        
        echo -e "${green}$index${none}    ${yellow}$uuid_short${none}    ${magenta}$email${none}"
        index=$((index+1))
    done
    
    echo "----------------------------------------------------------------"
    
    # 获取用户数量
    local user_count=$(echo "$port_info" | jq '.users | length')
    
    # 选择要修改的用户
    while :; do
        read -p "$(echo -e "请选择要修改的用户序号 [${green}1-$user_count${none}], 输入 0 取消: ")" user_index
        
        if [[ "$user_index" == "0" ]]; then
            echo -e "$yellow 操作已取消 $none"
            manage_port_users "$port"  # 返回用户管理菜单
            return
        fi
        
        if [[ -z "$user_index" ]] || ! [[ "$user_index" =~ ^[0-9]+$ ]] || [[ "$user_index" -lt 1 ]] || [[ "$user_index" -gt "$user_count" ]]; then
            error
            continue
        fi
        
        break
    done
    
    # 获取要修改的用户信息
    local user_to_modify=$(echo "$port_info" | jq -c ".users[$(($user_index-1))]")
    local old_uuid=$(echo "$user_to_modify" | jq -r '.uuid')
    local email=$(echo "$user_to_modify" | jq -r '.email')
    
    echo
    echo -e "$yellow 当前用户信息 $none"
    echo -e "UUID: ${cyan}$old_uuid${none}"
    echo -e "邮箱: ${cyan}$email${none}"
    
    # 生成随机UUID
    local ip=$([ "$netstack" = "6" ] && echo "$IPv6" || echo "$IPv4")
    local uuidSeed=${ip}$(cat /proc/sys/kernel/hostname)$(cat /etc/timezone)${port}$(date +%s%N)
    local default_uuid=$(curl -sL https://www.uuidtools.com/api/generate/v3/namespace/ns:dns/name/${uuidSeed} | grep -oP '[^-]{8}-[^-]{4}-[^-]{4}-[^-]{4}-[^-]{12}')
    
    # 输入新UUID
    while :; do
        echo -e "请输入新的UUID"
        read -p "$(echo -e "(默认: ${cyan}${default_uuid}${none}): ")" new_uuid
        [ -z "$new_uuid" ] && new_uuid=$default_uuid
        
        if [[ ! "$new_uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
            error
            continue
        fi
        
        # 检查UUID是否已存在
        if [[ "$new_uuid" != "$old_uuid" ]]; then
            local uuid_exists=$(echo "$port_info" | jq -r '.users[] | select(.uuid == "'$new_uuid'") | .uuid')
            if [[ -n "$uuid_exists" ]]; then
                echo -e "${red}UUID已存在，请使用其他UUID${none}"
                continue
            fi
        fi
        
        echo
        echo -e "$yellow 新UUID = ${cyan}$new_uuid${none}"
        break
    done
    
    # 备份当前配置
    cp "$PORT_INFO_FILE" "${PORT_INFO_FILE}.bak"
    
    # 修改用户UUID
    local updated_port_info=$(echo "$port_info" | jq ".users[$(($user_index-1))].uuid = \"$new_uuid\"")
    
    # 保存更新后的配置
    jq "(.ports[] | select(.port == $port)) |= $updated_port_info" "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
    
    # 验证更新后的JSON是否有效
    if jq -e . "${PORT_INFO_FILE}.tmp" > /dev/null; then
        mv "${PORT_INFO_FILE}.tmp" "$PORT_INFO_FILE"
        chmod 600 "$PORT_INFO_FILE"
        success "用户UUID修改成功!"
        log_info "修改端口 $port 用户UUID: $old_uuid -> $new_uuid, 邮箱: $email"
        
        # 更新配置文件并重启服务
        if ! update_config_file; then
            log_error "更新配置文件失败，尝试恢复备份"
            mv "${PORT_INFO_FILE}.bak" "$PORT_INFO_FILE"
            update_config_file
            systemctl restart xray
            pause
            manage_port_users "$port"
            return
        fi
        
        if ! systemctl restart xray; then
            log_error "重启Xray服务失败，尝试恢复备份"
            mv "${PORT_INFO_FILE}.bak" "$PORT_INFO_FILE"
            update_config_file
            systemctl restart xray
            pause
            manage_port_users "$port"
            return
        fi
    else
        rm -f "${PORT_INFO_FILE}.tmp"
        log_error "生成的JSON配置无效，UUID修改失败"
        # 恢复备份
        mv "${PORT_INFO_FILE}.bak" "$PORT_INFO_FILE"
        pause
        manage_port_users "$port"
        return
    fi
    
    # 生成连接信息
    local domain=$(echo "$port_info" | jq -r '.domain')
    local public_key=$(echo "$port_info" | jq -r '.public_key')
    local shortid=$(echo "$port_info" | jq -r '.shortid')
    
    # 生成链接
    if [[ $netstack = "6" ]]; then
        ip="[$ip]"
    fi
    
    vless_reality_url="vless://${new_uuid}@${ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=random&pbk=${public_key}&sid=${shortid}&#VLESS_R_${port}_${email}"
    
    echo
    echo "---------- 修改后的 VLESS Reality URL ----------"
    echo -e "${cyan}${vless_reality_url}${none}"
    echo
    
    # 生成二维码
    echo "二维码:"
    qrencode -t UTF8 "$vless_reality_url"
    
    # 保存信息到文件
    echo "$vless_reality_url" > "$HOME/vless_reality_${port}_${email}.txt"
    echo "链接信息已保存到 $HOME/vless_reality_${port}_${email}.txt"
    
    pause
    return
}

# 修改端口的UUID
modify_port_uuid() {
    local port=$1
    local port_info=$(get_port_info "$port")
    local old_uuid=$(echo "$port_info" | jq -r '.uuid')
    
    echo
    echo -e "$yellow 修改UUID $none"
    echo "----------------------------------------------------------------"
    echo -e "当前UUID: $cyan$old_uuid$none"
    
    # 生成新的默认UUID
    local ip=$([ "$netstack" = "6" ] && echo "$IPv6" || echo "$IPv4")
    local uuidSeed=${ip}$(cat /proc/sys/kernel/hostname)$(cat /etc/timezone)
    local default_uuid=$(curl -sL https://www.uuidtools.com/api/generate/v3/namespace/ns:dns/name/${uuidSeed} | grep -oP '[^-]{8}-[^-]{4}-[^-]{4}-[^-]{4}-[^-]{12}')
    
    while :; do
        echo -e "请输入新的UUID"
        read -p "$(echo -e "(留空使用随机UUID: ${cyan}${default_uuid}${none}): ")" new_uuid
        [ -z "$new_uuid" ] && new_uuid=$default_uuid
        
        if [[ ! "$new_uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
            error
            continue
        fi
        
        # 生成新的密钥
        local seed=$(echo -n ${new_uuid} | md5sum | head -c 32 | base64 -w 0 | tr '+/' '-_' | tr -d '=')
        local tmp_key=$(echo -n ${seed} | xargs xray x25519 -i)
        local new_private_key=$(echo ${tmp_key} | awk '{print $3}')
        local new_public_key=$(echo ${tmp_key} | awk '{print $6}')

        # 获取旧密钥对
        local old_private_key=$(echo "$port_info" | jq -r '.private_key')
        local old_public_key=$(echo "$port_info" | jq -r '.public_key')

        echo
        echo -e "$yellow 旧UUID = ${cyan}$old_uuid${none}"
        echo -e "$yellow 旧私钥 = ${cyan}$old_private_key${none}"
        echo -e "$yellow 旧公钥 = ${cyan}$old_public_key${none}"
        echo
        echo -e "$yellow 新UUID = ${cyan}$new_uuid${none}"
        echo -e "$yellow 新私钥 = ${cyan}$new_private_key${none}"
        echo -e "$yellow 新公钥 = ${cyan}$new_public_key${none}"
        echo
        
        # 生成新的ShortID
        local new_shortid=$(echo -n ${new_uuid} | sha1sum | head -c 16)
        
        echo
        echo -e "$yellow 新UUID = ${cyan}$new_uuid${none}"
        echo -e "$yellow 新私钥 = ${cyan}$new_private_key${none}"
        echo -e "$yellow 新公钥 = ${cyan}$new_public_key${none}"
        echo -e "$yellow 新ShortID = ${cyan}$new_shortid${none}"
        echo
        
        # 备份当前配置
        cp "$PORT_INFO_FILE" "${PORT_INFO_FILE}.bak"
        
        # 保存修改
        local domain=$(echo "$port_info" | jq -r '.domain')
        if ! save_port_info "$port" "$new_uuid" "$new_private_key" "$new_public_key" "$new_shortid" "$domain"; then
            log_error "保存端口配置失败"
            # 恢复备份
            mv "${PORT_INFO_FILE}.bak" "$PORT_INFO_FILE"
            return 1
        fi
        
        # 保持SOCKS5配置不变
        local socks5_config=$(echo "$port_info" | jq -r '.socks5')
        if [[ "$socks5_config" != "null" ]]; then
            local socks5_enabled=$(echo "$socks5_config" | jq -r '.enabled // false')
            if [[ "$socks5_enabled" == "true" ]]; then
                local socks5_address=$(echo "$socks5_config" | jq -r '.address')
                local socks5_port=$(echo "$socks5_config" | jq -r '.port')
                local auth_needed=$(echo "$socks5_config" | jq -r '.auth_needed')
                local auth_needed_yn=$([ "$auth_needed" == "true" ] && echo "y" || echo "n")
                local socks5_user=$(echo "$socks5_config" | jq -r '.username')
                local socks5_pass=$(echo "$socks5_config" | jq -r '.password')
                local udp_over_tcp=$(echo "$socks5_config" | jq -r '.udp_over_tcp')
                local udp_over_tcp_yn=$([ "$udp_over_tcp" == "true" ] && echo "y" || echo "n")
                
                set_port_socks5_config "$port" "y" "$socks5_address" "$socks5_port" "$auth_needed_yn" "$socks5_user" "$socks5_pass" "$udp_over_tcp_yn"
            fi
        fi
        
        success "UUID修改成功!"
        log_info "修改端口 $port 的UUID: $old_uuid -> $new_uuid"
        break
    done
}

# 修改端口的域名
modify_port_domain() {
    local port=$1
    local port_info=$(get_port_info "$port")
    local old_domain=$(echo "$port_info" | jq -r '.domain')
    
    echo
    echo -e "$yellow 修改域名(SNI) $none"
    echo "----------------------------------------------------------------"
    echo -e "当前域名: $cyan$old_domain$none"
    
    echo -e "请输入新的域名作为SNI"
    read -p "$(echo -e "(例如: learn.microsoft.com): ")" new_domain
    [ -z "$new_domain" ] && new_domain="learn.microsoft.com"
    
    echo
    echo -e "$yellow 新域名 = ${cyan}$new_domain${none}"
    
    # 保存修改
    local uuid=$(echo "$port_info" | jq -r '.uuid')
    local private_key=$(echo "$port_info" | jq -r '.private_key')
    local public_key=$(echo "$port_info" | jq -r '.public_key')
    local shortid=$(echo "$port_info" | jq -r '.shortid')
    
    save_port_info "$port" "$uuid" "$private_key" "$public_key" "$shortid" "$new_domain"
    
    # 保持SOCKS5配置不变
    local socks5_config=$(echo "$port_info" | jq -r '.socks5')
    if [[ "$socks5_config" != "null" ]]; then
        local socks5_enabled=$(echo "$socks5_config" | jq -r '.enabled // false')
        if [[ "$socks5_enabled" == "true" ]]; then
            local socks5_address=$(echo "$socks5_config" | jq -r '.address')
            local socks5_port=$(echo "$socks5_config" | jq -r '.port')
            local auth_needed=$(echo "$socks5_config" | jq -r '.auth_needed')
            local auth_needed_yn=$([ "$auth_needed" == "true" ] && echo "y" || echo "n")
            local socks5_user=$(echo "$socks5_config" | jq -r '.username')
            local socks5_pass=$(echo "$socks5_config" | jq -r '.password')
            local udp_over_tcp=$(echo "$socks5_config" | jq -r '.udp_over_tcp')
            local udp_over_tcp_yn=$([ "$udp_over_tcp" == "true" ] && echo "y" || echo "n")
            
            set_port_socks5_config "$port" "y" "$socks5_address" "$socks5_port" "$auth_needed_yn" "$socks5_user" "$socks5_pass" "$udp_over_tcp_yn"
        fi
    fi
    
    success "域名修改成功!"
    log_info "修改端口 $port 的域名: $old_domain -> $new_domain"
}

# 修改端口的ShortID
modify_port_shortid() {
    local port=$1
    local port_info=$(get_port_info "$port")
    local old_shortid=$(echo "$port_info" | jq -r '.shortid')
    local uuid=$(echo "$port_info" | jq -r '.uuid')
    
    echo
    echo -e "$yellow 修改ShortID $none"
    echo "----------------------------------------------------------------"
    echo -e "当前ShortID: $cyan$old_shortid$none"
    
    # 生成默认ShortID
    local default_shortid=$(echo -n ${uuid} | sha1sum | head -c 16)
    
    while :; do
        echo -e "请输入新的ShortID"
        read -p "$(echo -e "(默认ShortID: ${cyan}${default_shortid}${none}): ")" new_shortid
        [ -z "$new_shortid" ] && new_shortid=$default_shortid
        
        if [[ ${#new_shortid} -gt 16 ]]; then
            error
            continue
        elif [[ $(( ${#new_shortid} % 2 )) -ne 0 ]]; then
            error
            continue
        fi
        
        echo
        echo -e "$yellow 新ShortID = ${cyan}$new_shortid${none}"
        
        # 保存修改
        local private_key=$(echo "$port_info" | jq -r '.private_key')
        local public_key=$(echo "$port_info" | jq -r '.public_key')
        local domain=$(echo "$port_info" | jq -r '.domain')
        
        save_port_info "$port" "$uuid" "$private_key" "$public_key" "$new_shortid" "$domain"
        
        # 保持SOCKS5配置不变
        local socks5_config=$(echo "$port_info" | jq -r '.socks5')
        if [[ "$socks5_config" != "null" ]]; then
            local socks5_enabled=$(echo "$socks5_config" | jq -r '.enabled // false')
            if [[ "$socks5_enabled" == "true" ]]; then
                local socks5_address=$(echo "$socks5_config" | jq -r '.address')
                local socks5_port=$(echo "$socks5_config" | jq -r '.port')
                local auth_needed=$(echo "$socks5_config" | jq -r '.auth_needed')
                local auth_needed_yn=$([ "$auth_needed" == "true" ] && echo "y" || echo "n")
                local socks5_user=$(echo "$socks5_config" | jq -r '.username')
                local socks5_pass=$(echo "$socks5_config" | jq -r '.password')
                local udp_over_tcp=$(echo "$socks5_config" | jq -r '.udp_over_tcp')
                local udp_over_tcp_yn=$([ "$udp_over_tcp" == "true" ] && echo "y" || echo "n")
                
                set_port_socks5_config "$port" "y" "$socks5_address" "$socks5_port" "$auth_needed_yn" "$socks5_user" "$socks5_pass" "$udp_over_tcp_yn"
            fi
        fi
        
        success "ShortID修改成功!"
        log_info "修改端口 $port 的ShortID: $old_shortid -> $new_shortid"
        break
    done
}

# 修改端口的SOCKS5代理设置
modify_port_socks5() {
    local port=$1
    local port_info=$(get_port_info "$port")
    local socks5_config=$(echo "$port_info" | jq -r '.socks5')
    
    echo
    echo -e "$yellow 修改SOCKS5代理设置 $none"
    echo "----------------------------------------------------------------"
    
    if [[ "$socks5_config" != "null" && "$(echo "$socks5_config" | jq -r '.enabled // false')" == "true" ]]; then
        echo -e "当前状态: ${green}已启用${none}"
        local socks5_address=$(echo "$socks5_config" | jq -r '.address')
        local socks5_port=$(echo "$socks5_config" | jq -r '.port')
        local auth_needed=$(echo "$socks5_config" | jq -r '.auth_needed')
        local socks5_user=$(echo "$socks5_config" | jq -r '.username')
        local socks5_pass=$(echo "$socks5_config" | jq -r '.password')
        local udp_over_tcp=$(echo "$socks5_config" | jq -r '.udp_over_tcp')
        
        echo -e "SOCKS5服务器: $cyan$socks5_address:$socks5_port$none"
        if [[ "$auth_needed" == "true" ]]; then
            echo -e "认证: ${green}启用${none} (用户名: $cyan$socks5_user$none)"
            echo -e "认证: ${green}启用${none} (密码: $cyan$socks5_pass$none)"
        else
            echo -e "认证: ${red}禁用${none}"
        fi
        
        if [[ "$udp_over_tcp" == "true" ]]; then
            echo -e "UDP over TCP: ${green}启用${none}"
        else
            echo -e "UDP over TCP: ${red}禁用${none}"
        fi
        
        echo
        echo -e "是否要${red}禁用${none} SOCKS5代理?"
        read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" disable_socks5
        
        if [[ "$disable_socks5" == "y" ]]; then
            # 禁用SOCKS5
            set_port_socks5_config "$port" "n" "" "" "" "" "" ""
            success "SOCKS5代理已禁用!"
            log_info "禁用端口 $port 的SOCKS5代理"
        else
            # 修改SOCKS5设置
            echo
            echo -e "请输入新的SOCKS5服务器地址 (当前: $cyan$socks5_address$none)"
            read -p "$(echo -e "(留空保持不变): ")" new_socks5_address
            [ -z "$new_socks5_address" ] && new_socks5_address=$socks5_address
            
            echo -e "请输入新的SOCKS5端口 (当前: $cyan$socks5_port$none)"
            read -p "$(echo -e "(留空保持不变): ")" new_socks5_port
            [ -z "$new_socks5_port" ] && new_socks5_port=$socks5_port
            
            echo -e "是否需要用户名密码认证? (当前: $cyan$([ "$auth_needed" == "true" ] && echo "是" || echo "否")$none)"
            read -p "$(echo -e "(y/n, 默认: ${cyan}$([ "$auth_needed" == "true" ] && echo "y" || echo "n")${none}): ")" new_auth_needed
            [ -z "$new_auth_needed" ] && new_auth_needed=$([ "$auth_needed" == "true" ] && echo "y" || echo "n")
            
            new_socks5_user=$socks5_user
            new_socks5_pass=$socks5_pass
            if [[ "$new_auth_needed" == "y" ]]; then
                echo -e "请输入用户名 (当前: $cyan$socks5_user$none)"
                read -p "$(echo -e "(留空保持不变): ")" temp_user
                [ -n "$temp_user" ] && new_socks5_user=$temp_user
                
                echo -e "请输入密码 (当前: $cyan$socks5_pass$none)"
                read -p "$(echo -e "(留空保持不变): ")" temp_pass
                echo  # 为了换行
                [ -n "$temp_pass" ] && new_socks5_pass=$temp_pass
            fi
            
            echo -e "是否启用UDP over TCP? (当前: $cyan$([ "$udp_over_tcp" == "true" ] && echo "是" || echo "否")$none)"
            read -p "$(echo -e "(y/n, 默认: ${cyan}$([ "$udp_over_tcp" == "true" ] && echo "y" || echo "n")${none}): ")" new_udp_over_tcp
            [ -z "$new_udp_over_tcp" ] && new_udp_over_tcp=$([ "$udp_over_tcp" == "true" ] && echo "y" || echo "n")
            
            # 保存SOCKS5设置
            set_port_socks5_config "$port" "y" "$new_socks5_address" "$new_socks5_port" "$new_auth_needed" "$new_socks5_user" "$new_socks5_pass" "$new_udp_over_tcp"
            
            success "SOCKS5代理设置已更新!"
            log_info "更新端口 $port 的SOCKS5代理设置"
        fi
    else
        echo -e "当前状态: ${red}未启用${none}"
        echo
        echo -e "是否要${green}启用${none} SOCKS5代理?"
        read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" enable_socks5
        
        if [[ "$enable_socks5" == "y" ]]; then
            # 启用SOCKS5
            configure_socks5_for_port "$port"
        fi
    fi
}

# 删除端口配置
delete_port_configuration() {
    echo
    echo -e "$yellow 删除端口配置 $none"
    echo "----------------------------------------------------------------"
    
    if [[ ! -s "$PORT_INFO_FILE" ]] || [[ $(jq '.ports | length' "$PORT_INFO_FILE") -eq 0 ]]; then
        echo -e "$red 目前没有配置任何端口，请先添加端口配置 $none"
        return
    fi
    
    # 显示所有端口
    list_port_configurations
    
    # 选择要删除的端口
    local port_count=$(jq '.ports | length' "$PORT_INFO_FILE")
    while :; do
        read -p "$(echo -e "请选择要删除的配置序号 [${green}1-$port_count${none}], 输入 0 取消: ")" port_index
        
        if [[ "$port_index" == "0" ]]; then
            echo -e "$yellow 操作已取消 $none"
            return
        fi
        
        if [[ -z "$port_index" ]] || ! [[ "$port_index" =~ ^[0-9]+$ ]] || [[ "$port_index" -lt 1 ]] || [[ "$port_index" -gt "$port_count" ]]; then
            error
            continue
        fi
        
        # 获取对应的端口信息
        local selected_port_info=$(jq -c ".ports[$(($port_index-1))]" "$PORT_INFO_FILE")
        local port=$(echo "$selected_port_info" | jq -r '.port')
        
        echo
        echo -e "$yellow 确认要删除端口 ${cyan}$port${none} 的配置吗? $none"
        read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" confirm_delete
        
        if [[ "$confirm_delete" == "y" ]]; then
            # 删除端口信息
            delete_port_info "$port"
            
            # 更新配置文件
            update_config_file
            
            # 删除此端口生成的所有txt文件
            echo -e "$yellow 删除端口 ${cyan}$port${none} 生成的所有连接信息文件... $none"
            
            # 匹配所有包含端口号的连接信息文件
            local files_to_delete=($HOME/vless_reality_${port}*.txt)
            
            # 检查找到的文件数量
            if [[ ${#files_to_delete[@]} -gt 0 && -f "${files_to_delete[0]}" ]]; then
                rm -f $HOME/vless_reality_${port}*.txt
                log_info "删除了端口 $port 生成的 ${#files_to_delete[@]} 个连接信息文件"
                echo -e "$green 成功删除 ${#files_to_delete[@]} 个连接信息文件 $none"
            else
                log_info "未找到端口 $port 生成的连接信息文件"
                echo -e "$yellow 未找到端口 ${cyan}$port${none} 生成的连接信息文件 $none"
            fi
            
            # 重启 Xray
            echo
            echo -e "$yellow 重启 Xray 服务... $none"
            if systemctl restart xray; then
                echo -e "$green Xray 服务重启成功! $none"
                log_info "删除端口 $port 配置后重启 Xray 成功"
            else
                echo -e "$red Xray 服务重启失败，请手动检查! $none"
                log_error "删除端口 $port 配置后重启 Xray 失败"
            fi
            
            success "端口 $port 配置已删除!"
            log_info "端口 $port 配置已删除"
        else
            echo -e "$yellow 操作已取消 $none"
        fi
        
        break
    done
    
    pause
}

# 卸载 Xray 的函数
uninstall_xray() {
    echo
    echo -e "$yellow 卸载 Xray $none"
    echo "----------------------------------------------------------------"
    
    echo -e "${red}警告: 此操作将完全卸载 Xray 并删除所有配置信息!${none}"
    echo -e "${red}      所有端口配置和连接信息将被清除!${none}"
    echo
    
    read -p "$(echo -e "确认卸载? 输入 ${red}uninstall${none} 确认操作: ")" confirm
    
    if [[ "$confirm" != "uninstall" ]]; then
        echo -e "$yellow 操作已取消 $none"
        return
    fi
    
    # 卸载 Xray
    echo -e "$yellow 正在卸载 Xray... $none"
    
    # 使用官方脚本卸载
    if bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge; then
        echo -e "$green Xray 卸载成功! $none"
    else
        echo -e "$red Xray 卸载失败! 请检查错误信息 $none"
    fi
    
    # 删除配置信息文件
    if [ -f "$PORT_INFO_FILE" ]; then
        rm -f "$PORT_INFO_FILE"
        echo -e "$green 端口配置信息已删除 $none"
    fi
    
    # 删除连接信息文件(vless_reality开头的txt文件)
    rm -f "$HOME/vless_reality_"*.txt 2>/dev/null
    echo -e "$green 连接信息文件已删除 $none"
    
    # 删除日志文件
    if [ -f "$LOG_FILE" ]; then
        rm -f "$LOG_FILE"
        echo -e "$green 日志文件已删除 $none"
    fi
    
    echo
    echo -e "$green Xray 已完全卸载! $none"
    pause
    
    # 询问是否退出脚本
    read -p "$(echo -e "是否退出脚本? (y/n, 默认: ${cyan}y${none}): ")" exit_script
    [ -z "$exit_script" ] && exit_script="y"
    
    if [[ "$exit_script" == "y" ]]; then
        exit 0
    else
        show_menu
    fi
}

# 显示所有/特定端口的连接信息
show_all_connections() {
    echo
    echo -e "$yellow 端口连接信息 $none"
    echo "----------------------------------------------------------------"
    
    if [[ ! -s "$PORT_INFO_FILE" ]] || [[ $(jq '.ports | length' "$PORT_INFO_FILE") -eq 0 ]]; then
        echo -e "$red 目前没有配置任何端口，请先添加端口配置 $none"
        return
    fi
    
    # 获取本机IP
    if ! get_local_ips; then
        echo -e "${red}获取IP地址失败!${none}"
        return
    fi
    
    # 端口选择菜单
    echo -e "请选择要显示的端口:"
    echo -e "  ${green}0.${none} 显示所有端口"
    
    # 获取所有端口并存储到数组
    local port_list=()
    local port_count=$(jq '.ports | length' "$PORT_INFO_FILE")
    
    # 提前获取所有端口并存到数组中，避免在循环中创建数组的问题
    for ((i=0; i<$port_count; i++)); do
        local port=$(jq -r ".ports[$i].port" "$PORT_INFO_FILE")
        port_list+=("$port")
        echo -e "  ${green}$((i+1)).${none} 端口 $port"
    done
    
    # 读取端口选择
    read -p "$(echo -e "请选择 [${green}0-$port_count${none}]: ")" port_choice
    
    # 默认为0（显示所有端口）
    [ -z "$port_choice" ] && port_choice=0
    
    # 根据网络环境选择IP
    if [[ -n "$IPv4" ]]; then
        ip=$IPv4
        netstack=4
    elif [[ -n "$IPv6" ]]; then
        ip=$IPv6
        netstack=6
    fi
    
    # 处理选择
    if [[ "$port_choice" == "0" ]]; then
        # 显示所有端口
        echo
        echo -e "$yellow 显示所有端口的连接信息 $none"
        echo "----------------------------------------------------------------"
        
        # 遍历所有端口
        for ((i=0; i<$port_count; i++)); do
            local port=${port_list[i]}
            local port_info=$(jq -c ".ports[] | select(.port == $port)" "$PORT_INFO_FILE")
            local uuid=$(echo "$port_info" | jq -r '.uuid')
            local public_key=$(echo "$port_info" | jq -r '.public_key')
            local shortid=$(echo "$port_info" | jq -r '.shortid')
            local domain=$(echo "$port_info" | jq -r '.domain')
            
            # 检查是否有多个用户
            local user_count=$(echo "$port_info" | jq '.users | length')
            
            echo
            echo -e "${yellow}端口 $port 连接信息 (共 $user_count 个用户)${none}"
            echo "----------------------------------------------------------------"
            
            if [[ "$user_count" -gt 0 ]]; then
                # 显示所有用户的连接信息
                for ((j=0; j<$user_count; j++)); do
                    local user_info=$(echo "$port_info" | jq -c ".users[$j]")
                    local user_uuid=$(echo "$user_info" | jq -r '.uuid')
                    local user_email=$(echo "$user_info" | jq -r '.email')
                    
                    echo -e "${cyan}用户: $user_email${none}"
                    generate_user_connection_info "$port" "$user_uuid" "$public_key" "$shortid" "$domain" "$ip" "$netstack" "$user_email"
                    echo "----------------------------------------------------------------"
                done
            else
                # 使用端口的主UUID（兼容旧配置）
                generate_user_connection_info "$port" "$uuid" "$public_key" "$shortid" "$domain" "$ip" "$netstack" "默认用户"
                echo "----------------------------------------------------------------"
            fi
        done
    elif [[ "$port_choice" =~ ^[0-9]+$ ]] && [[ "$port_choice" -ge 1 ]] && [[ "$port_choice" -le "$port_count" ]]; then
        # 显示特定端口
        local selected_port=${port_list[$((port_choice-1))]}
        local port_info=$(jq -c ".ports[] | select(.port == $selected_port)" "$PORT_INFO_FILE")
        local uuid=$(echo "$port_info" | jq -r '.uuid')
        local public_key=$(echo "$port_info" | jq -r '.public_key')
        local shortid=$(echo "$port_info" | jq -r '.shortid')
        local domain=$(echo "$port_info" | jq -r '.domain')
        
        # 检查是否有多个用户
        local user_count=$(echo "$port_info" | jq '.users | length')
        
        echo
        echo -e "${yellow}端口 $selected_port 连接信息 (共 $user_count 个用户)${none}"
        echo "----------------------------------------------------------------"
        
        # 如果只有一个用户，直接显示
        if [[ "$user_count" -eq 1 ]]; then
            local user_info=$(echo "$port_info" | jq -c '.users[0]')
            local user_uuid=$(echo "$user_info" | jq -r '.uuid')
            local user_email=$(echo "$user_info" | jq -r '.email')
            
            echo -e "${cyan}用户: $user_email${none}"
            generate_user_connection_info "$selected_port" "$user_uuid" "$public_key" "$shortid" "$domain" "$ip" "$netstack" "$user_email"
        elif [[ "$user_count" -gt 1 ]]; then
            # 显示用户选择菜单
            echo -e "请选择要显示的用户:"
            echo -e "  ${green}0.${none} 显示所有用户"
            
            # 提前获取所有用户信息
            local user_emails=()
            local user_uuids=()
            
            for ((i=0; i<$user_count; i++)); do
                local user_info=$(echo "$port_info" | jq -c ".users[$i]")
                local user_uuid=$(echo "$user_info" | jq -r '.uuid')
                local user_email=$(echo "$user_info" | jq -r '.email')
                user_emails+=("$user_email")
                user_uuids+=("$user_uuid")
                
                # 截取UUID的开头和结尾部分，中间用省略号
                local uuid_short="${user_uuid:0:8}...${user_uuid:24}"
                echo -e "  ${green}$((i+1)).${none} $user_email (UUID: $uuid_short)"
            done
            
            # 读取用户选择
            read -p "$(echo -e "请选择 [${green}0-$user_count${none}]: ")" user_choice
            
            # 默认为0（显示所有用户）
            [ -z "$user_choice" ] && user_choice=0
            
            echo
            # 处理用户选择
            if [[ "$user_choice" == "0" ]]; then
                # 显示所有用户
                for ((i=0; i<$user_count; i++)); do
                    local user_email=${user_emails[i]}
                    local user_uuid=${user_uuids[i]}
                    
                    echo -e "${cyan}用户: $user_email${none}"
                    generate_user_connection_info "$selected_port" "$user_uuid" "$public_key" "$shortid" "$domain" "$ip" "$netstack" "$user_email"
                    echo "----------------------------------------------------------------"
                done
            elif [[ "$user_choice" =~ ^[0-9]+$ ]] && [[ "$user_choice" -ge 1 ]] && [[ "$user_choice" -le "$user_count" ]]; then
                # 显示特定用户
                local selected_index=$((user_choice-1))
                local user_email=${user_emails[$selected_index]}
                local user_uuid=${user_uuids[$selected_index]}
                
                echo -e "${cyan}用户: $user_email${none}"
                generate_user_connection_info "$selected_port" "$user_uuid" "$public_key" "$shortid" "$domain" "$ip" "$netstack" "$user_email"
            else
                error
            fi
        else
            # 使用端口的主UUID（兼容旧配置）
            generate_user_connection_info "$selected_port" "$uuid" "$public_key" "$shortid" "$domain" "$ip" "$netstack" "默认用户"
        fi
    else
        error
    fi
    
    pause
}

# 为单个用户生成连接信息
generate_user_connection_info() {
    local port=$1
    local uuid=$2
    local public_key=$3
    local shortid=$4
    local domain=$5
    local ip=$6
    local netstack=$7
    local email=$8
    
    echo
    echo "---------- 端口 $port 的 Xray 配置信息 -------------"
    echo -e "$green ---提示..这是 VLESS Reality 服务器配置--- $none"
    echo -e "$yellow 地址 (Address) = $cyan${ip}$none"
    echo -e "$yellow 端口 (Port) = ${cyan}${port}${none}"
    echo -e "$yellow 用户ID (User ID / UUID) = $cyan${uuid}$none"
    echo -e "$yellow 流控 (Flow) = ${cyan}xtls-rprx-vision${none}"
    echo -e "$yellow 加密 (Encryption) = ${cyan}none${none}"
    echo -e "$yellow 传输协议 (Network) = ${cyan}tcp$none"
    echo -e "$yellow 伪装类型 (header type) = ${cyan}none$none"
    echo -e "$yellow 底层传输安全 (TLS) = ${cyan}reality$none"
    echo -e "$yellow SNI = ${cyan}${domain}$none"
    echo -e "$yellow 指纹 (Fingerprint) = ${cyan}random${none}"
    echo -e "$yellow 公钥 (PublicKey) = ${cyan}${public_key}$none"
    echo -e "$yellow ShortId = ${cyan}${shortid}$none"
    echo -e "$yellow SpiderX = ${cyan}${none}"
    
    # 检查是否配置了SOCKS5代理
    local port_info=$(get_port_info "$port")
    if [[ -n "$port_info" ]]; then
        local socks5_enabled=$(echo "$port_info" | jq -r '.socks5.enabled // false')
        if [[ "$socks5_enabled" == "true" ]]; then
            local socks5_address=$(echo "$port_info" | jq -r '.socks5.address')
            local socks5_port=$(echo "$port_info" | jq -r '.socks5.port')
            echo -e "$yellow SOCKS5代理 = ${cyan}已启用 (${socks5_address}:${socks5_port})$none"
        fi
    fi
    
    # 生成链接
    if [[ $netstack = "6" ]]; then
        ip="[$ip]"
    fi
    
    # 使用邮箱标识用户连接
    local email_tag=""
    if [[ -n "$email" && "$email" != "默认用户" ]]; then
        email_tag="_${email}"
    fi
    
    vless_reality_url="vless://${uuid}@${ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=random&pbk=${public_key}&sid=${shortid}&#VLESS_R_${port}${email_tag}"
    
    echo
    echo "---------- VLESS Reality URL ----------"
    echo -e "${cyan}${vless_reality_url}${none}"
    echo
    
    # 生成二维码
    echo "二维码:"
    qrencode -t UTF8 "$vless_reality_url"
    
    # 保存信息到文件
    local filename="vless_reality_${port}"
    if [[ -n "$email" && "$email" != "默认用户" ]]; then
        # 清理邮箱中可能导致文件名问题的字符
        local sanitized_email=$(echo "$email" | sed 's/[^a-zA-Z0-9@._-]/_/g')
        filename="${filename}_${sanitized_email}"
    fi
    
    echo "$vless_reality_url" > "$HOME/${filename}.txt"
    echo
    echo "链接信息已保存到 $HOME/${filename}.txt"
}


# 格式化字节大小
format_bytes() {
    local bytes=$1
    local suffix=("B" "KB" "MB" "GB" "TB")
    local i=0
    local value=$bytes
    
    while (( value > 1024 && i < 4 )); do
        value=$(echo "scale=2; $value / 1024" | bc)
        ((i++))
    done
    
    echo "$value ${suffix[$i]}"
}




# 显示使用帮助信息
show_help() {
    echo
    echo -e "$yellow Xray 多端口管理脚本使用帮助 $none"
    echo "----------------------------------------------------------------"
    echo -e "  ${green}1.${none} 安装/重装 Xray: 安装或重新安装 Xray，并初始化配置。"
    echo -e "  ${green}2.${none} 添加新端口配置: 添加新的 VLESS Reality 端口，并可选配置 SOCKS5 代理。"
    echo -e "  ${green}3.${none} 查看所有端口配置: 显示当前配置的所有端口信息。"
    echo -e "  ${green}4.${none} 修改端口配置: 修改现有端口的 UUID、域名、ShortID 或 SOCKS5 代理设置。"
    echo -e "  ${green}5.${none} 删除端口配置: 删除指定端口的配置。"
    echo -e "  ${green}6.${none} 显示所有端口连接信息: 生成并显示所有端口的详细连接信息，包括二维码。"
    echo -e "  ${green}7.${none} 更新 GeoIP 和 GeoSite 数据: 手动更新 Xray 的 GeoIP 和 GeoSite 数据库。"
    echo -e "  ${green}8.${none} 流量统计: 显示各端口的流量使用情况（需配置 Xray API）。"
    echo -e "  ${green}9.${none} 设置定时更新: 配置定时任务自动更新 GeoIP 和 GeoSite 数据。"
    echo -e "  ${green}10.${none} 备份与恢复: 备份当前配置或从备份恢复配置。"
    echo -e "  ${green}11.${none} 检查脚本更新: 检查并更新脚本到最新版本。"
    echo -e "  ${green}12.${none} 查看日志: 显示 Xray 运行日志。"
    echo -e "  ${green}0.${none} 退出: 退出脚本。"
    echo "----------------------------------------------------------------"
    echo -e "当前版本: ${cyan}$VERSION${none}"
    echo -e "Bug 反馈: ${cyan}https://github.com/your-username/xray-multi-port/issues${none}"
    echo "----------------------------------------------------------------"
    
    pause
}

# 查看Xray日志
view_xray_logs() {
    echo
    echo -e "$yellow 查看 Xray 日志 $none"
    echo "----------------------------------------------------------------"
    
    echo -e "请选择要查看的日志:"
    echo -e "  ${green}1.${none} 访问日志 (access.log)"
    echo -e "  ${green}2.${none} 错误日志 (error.log)"
    echo -e "  ${green}3.${none} 返回"
    
    read -p "$(echo -e "请选择 [${green}1-3${none}]: ")" log_choice
    
    case $log_choice in
        1)
            if [[ -f "/var/log/xray/access.log" ]]; then
                echo -e "${yellow}访问日志 (最后 100 行):${none}"
                echo "----------------------------------------------------------------"
                tail -n 100 /var/log/xray/access.log
            else
                echo -e "${red}访问日志文件不存在${none}"
            fi
            ;;
            
        2)
            if [[ -f "/var/log/xray/error.log" ]]; then
                echo -e "${yellow}错误日志 (最后 100 行):${none}"
                echo "----------------------------------------------------------------"
                tail -n 100 /var/log/xray/error.log
            else
                echo -e "${red}错误日志文件不存在${none}"
            fi
            ;;
            
        3)
            return
            ;;
            
        *)
            error
            ;;
    esac
    
    pause
}

# 安装 Xray 的主函数
install_xray() {
    # 说明
    echo
    echo -e "$yellow 此脚本仅兼容于 Debian 10+ 系统. 如果你的系统不符合,请Ctrl+C退出脚本 $none"
    echo -e "脚本版本: ${cyan}$VERSION${none}"
    echo "----------------------------------------------------------------"

    # 安装依赖
    echo -e "${yellow}安装依赖...${none}"
    apt update
    apt install -y curl sudo jq qrencode net-tools lsof wget
    
    # 检查是否已安装Xray
    if command -v xray &> /dev/null; then
        echo -e "${yellow}检测到已安装 Xray，是否重新安装?${none}"
        read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" reinstall
        
        if [[ "$reinstall" != "y" ]]; then
            echo -e "${yellow}跳过安装 Xray${none}"
            return
        fi
    fi

    # Xray官方脚本安装最新版本
    echo
    echo -e "${yellow}Xray官方脚本安装最新版本$none"
    echo "----------------------------------------------------------------"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # 检查安装结果
    if ! command -v xray &> /dev/null; then
        echo -e "${red}Xray 安装失败，请检查网络连接或手动安装${none}"
        log_error "Xray 安装失败"
        return 1
    fi

    # 更新 geodata
    update_geodata

    # 打开BBR
    echo
    echo -e "$yellow打开BBR$none"
    echo "----------------------------------------------------------------"
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.conf
    echo "net.core.default_qdisc = fq" >>/etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    
    # 确保配置目录存在
    init_directories
    
    # 提示用户添加端口
    echo
    echo -e "$green Xray 安装完成！$none"
    log_info "Xray 安装完成"

    # 优化TCP参数
    optimize_tcp

    echo -e "$yellow 接下来您需要添加端口配置 $none"
    pause
    
    # 添加第一个端口配置
    add_port_configuration
}

# 主菜单
show_menu() {
    echo
    echo "---------- Xray 多端口管理脚本 V${VERSION} -------------"
    echo -e "  ${green}1.${none} 安装/重装 Xray"
    echo -e "  ${green}2.${none} 添加新端口配置"
    echo -e "  ${green}3.${none} 查看所有端口配置"
    echo -e "  ${green}4.${none} 修改端口配置"
    echo -e "  ${green}5.${none} 删除端口配置"
    echo -e "  ${green}6.${none} 显示所有端口连接信息"
    echo -e "  ${green}7.${none} 更新 GeoIP 和 GeoSite 数据"
    echo -e "  ${green}8.${none} 备份与恢复"
    echo -e "  ${green}9.${none} 查看 Xray 日志"
    echo -e "  ${green}10.${none} 帮助信息"
    echo -e "  ${green}11.${none} 卸载 Xray"
    echo -e "  ${green}0.${none} 退出"
    echo "------------------------------------"
    read -p "请选择 [0-11]: " choice

    case $choice in
        1)
            install_xray
            ;;
        2)
            add_port_configuration
            ;;
        3)
            list_port_configurations
            pause
            ;;
        4)
            modify_port_configuration
            ;;
        5)
            delete_port_configuration
            ;;
        6)
            show_all_connections
            ;;
        7)
            update_geodata
            ;;
        8)
            echo
            echo -e "  ${green}1.${none} 备份配置"
            echo -e "  ${green}2.${none} 恢复配置"
            echo -e "  ${green}0.${none} 返回上级菜单"
            read -p "请选择 [0-2]: " backup_choice
            case $backup_choice in
                1)
                    backup_configuration
                    ;;
                2)
                    restore_configuration
                    ;;
                *)
                    ;;
            esac
            ;;
        9)
            view_xray_logs
            ;;
        10)
            show_help
            ;;
        11)
            uninstall_xray
            ;;
        0)
            echo -e "${green}感谢使用 Xray 多端口管理脚本${none}"
            exit 0
            ;;
        *)
            error
            ;;
    esac
    
    # 返回主菜单
    show_menu
}

# 检查是否以root权限运行
check_root

# 初始化必要的目录和文件
init_directories

# 检查依赖
check_dependencies

# 记录脚本启动信息
log_info "脚本启动，版本 $VERSION"

# 如果没有带参数运行，显示菜单
if [ $# -eq 0 ]; then
    show_menu
else
    # 如果带参数运行，直接安装
    install_xray "$@"
fi
