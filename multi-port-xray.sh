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

# 配置文件路径
CONFIG_FILE="/usr/local/etc/xray/config.json"
PORT_INFO_FILE="$HOME/.xray_port_info"

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
            ip=$(curl -"${ip_type}"s --interface "$interface" -m "$timeout" "$api" | grep -oP "ip=\K.*$")
        else
            ip=$(curl -"${ip_type}"s --interface "$interface" -m "$timeout" "$api")
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
                success=true
            fi
        fi
        
        # 尝试获取IPv6
        if [[ -z "$IPv6" ]]; then
            Public_IPv6=$(get_public_ip 6 "$i")
            if [[ -n "$Public_IPv6" ]]; then
                IPv6="$Public_IPv6"
                echo -e "${green}在接口 $i 上成功获取到IPv6: $IPv6${none}"
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
            success=true
        fi
    fi
    
    if [[ -z "$IPv6" ]]; then
        echo -e "${yellow}尝试直接获取IPv6...${none}"
        IPv6=$(get_public_ip 6)
        if [[ -n "$IPv6" ]]; then
            echo -e "${green}成功获取到IPv6: $IPv6${none}"
            success=true
        fi
    fi

    # 检查是否获取到任何IP
    if ! $success; then
        echo -e "${red}警告: 未能获取到任何公共IP地址${none}"
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
}

warn() {
    echo -e "\n$yellow $1 $none\n"
}

success() {
    echo -e "\n$green $1 $none\n"
}

pause
}() {
    read -rsp "$(echo -e "按 $green Enter 回车键 $none 继续....或按 $red Ctrl + C $none 取消.")" -d $'\n'
    echo
}

# 更新 Xray GeoIP 和 GeoSite 数据
update_geodata() {
    echo
    echo -e "$yellow 更新 Xray GeoIP 和 GeoSite 数据 $none"
    echo "----------------------------------------------------------------"
    
    # 使用官方脚本更新
    if bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata; then
        echo
        echo -e "$green 数据库更新成功! $none"
        
        # 重启 Xray 服务
        echo
        echo -e "$yellow 重启 Xray 服务... $none"
        if systemctl restart xray; then
            echo -e "$green Xray 服务重启成功! $none"
        else
            echo -e "$red Xray 服务重启失败，请手动检查! $none"
        fi
    else
        echo -e "$red 数据库更新失败! $none"
        echo
        echo -e "$yellow 尝试手动更新... $none"
        
        # 手动下载更新
        if wget -O /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat && \
           wget -O /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat; then
            echo -e "$green 数据库手动更新成功! $none"
            
            # 重启 Xray 服务
            echo
            echo -e "$yellow 重启 Xray 服务... $none"
            if systemctl restart xray; then
                echo -e "$green Xray 服务重启成功! $none"
            else
                echo -e "$red Xray 服务重启失败，请手动检查! $none"
            fi
        else
            echo -e "$red 数据库手动更新失败! $none"
        fi
    fi
    
    # 显示当前 Xray 版本信息
    echo
    echo -e "$yellow 当前 Xray 版本信息: $none"
    xray --version
    echo
    pause
}

# 保存端口配置信息
save_port_info() {
    local port=$1
    local uuid=$2
    local private_key=$3
    local public_key=$4
    local shortid=$5
    local domain=$6
    local socks5_enabled=$7
    local socks5_info=$8

    # 检查是否已存在相同端口的记录，如果存在则删除
    if [ -f "$PORT_INFO_FILE" ]; then
        sed -i "/^$port:/d" "$PORT_INFO_FILE"
    fi

    # 添加新的端口记录
    echo "$port:$uuid:$private_key:$public_key:$shortid:$domain:$socks5_enabled:$socks5_info" >> "$PORT_INFO_FILE"
}

# 获取所有端口配置信息
get_all_port_info() {
    if [ -f "$PORT_INFO_FILE" ]; then
        cat "$PORT_INFO_FILE"
    else
        echo ""
    fi
}

# 获取特定端口的配置信息
get_port_info() {
    local port=$1
    if [ -f "$PORT_INFO_FILE" ]; then
        grep "^$port:" "$PORT_INFO_FILE"
    else
        echo ""
    fi
}

# 检查端口是否已配置
check_port_exists() {
    local port=$1
    if [ -f "$PORT_INFO_FILE" ]; then
        if grep -q "^$port:" "$PORT_INFO_FILE"; then
            return 0  # 端口已存在
        fi
    fi
    return 1  # 端口不存在
}

# 删除特定端口的配置信息
delete_port_info() {
    local port=$1
    if [ -f "$PORT_INFO_FILE" ]; then
        sed -i "/^$port:/d" "$PORT_INFO_FILE"
    fi
}

# 读取配置文件并添加新的入站配置
update_config_file() {
    # 备份当前配置
    cp "$CONFIG_FILE" "$CONFIG_FILE.bak"
    
    # 读取当前配置到临时文件
    local temp_config=$(mktemp)
    jq . "$CONFIG_FILE" > "$temp_config"
    
    # 读取所有端口信息
    local port_list=()
    if [ -f "$PORT_INFO_FILE" ]; then
        while read -r line; do
            port=$(echo "$line" | cut -d: -f1)
            port_list+=("$port")
        done < "$PORT_INFO_FILE"
    fi
    
    # 创建新的配置
    jq 'del(.inbounds)' "$temp_config" > "$temp_config.new"
    
    # 添加inbounds数组
    jq '. += {"inbounds": []}' "$temp_config.new" > "$temp_config"
    
    # 添加每个端口的配置
    for port in "${port_list[@]}"; do
        port_info=$(get_port_info "$port")
        
        uuid=$(echo "$port_info" | cut -d: -f2)
        private_key=$(echo "$port_info" | cut -d: -f3)
        shortid=$(echo "$port_info" | cut -d: -f5)
        domain=$(echo "$port_info" | cut -d: -f6)
        socks5_enabled=$(echo "$port_info" | cut -d: -f7)
        
        # 创建入站配置
        cat > "$temp_config.inbound" << EOL
{
  "listen": "0.0.0.0",
  "port": ${port},
  "protocol": "vless",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "flow": "xtls-rprx-vision"
      }
    ],
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
  }
}
EOL

        # 添加入站配置到总配置
        jq '.inbounds += [input]' "$temp_config" "$temp_config.inbound" > "$temp_config.new"
        mv "$temp_config.new" "$temp_config"
    done
    
    # 处理SOCKS5代理输出
    socks5_outbounds=()
    socks5_routing_rules=()
    
    for port in "${port_list[@]}"; do
        port_info=$(get_port_info "$port")
        socks5_enabled=$(echo "$port_info" | cut -d: -f7)
        socks5_info=$(echo "$port_info" | cut -d: -f8)
        
        if [[ "$socks5_enabled" == "y" ]]; then
            IFS='|' read -r socks5_address socks5_port auth_needed socks5_user socks5_pass udp_over_tcp <<< "$socks5_info"
            
            # 为每个SOCKS5配置创建一个唯一标识
            socks5_tag="socks5-out-$port"
            
            # 创建SOCKS5出站配置
            cat > "$temp_config.socks5" << EOL
{
  "protocol": "socks",
  "settings": {
    "servers": [
      {
        "address": "$socks5_address",
        "port": $socks5_port
EOL

            if [[ "$auth_needed" == "y" ]]; then
                cat >> "$temp_config.socks5" << EOL
        ,"users": [{"user": "$socks5_user","pass": "$socks5_pass"}]
EOL
            fi
            
            cat >> "$temp_config.socks5" << EOL
      }
    ]
  }
EOL

            if [[ "$udp_over_tcp" == "y" ]]; then
                cat >> "$temp_config.socks5" << EOL
  ,"streamSettings": {"sockopt": {"udpFragmentSize": 1400,"tcpFastOpen": true,"tcpKeepAliveInterval": 15}},"transportLayer": true
EOL
            fi
            
            cat >> "$temp_config.socks5" << EOL
  ,"tag": "$socks5_tag"
}
EOL

            # 添加SOCKS5出站配置
            jq '.outbounds += [input]' "$temp_config" "$temp_config.socks5" > "$temp_config.new"
            mv "$temp_config.new" "$temp_config"
            
            # 创建路由规则
            network_type=$([ "$udp_over_tcp" = "y" ] && echo "tcp,udp" || echo "tcp")
            cat > "$temp_config.rule" << EOL
{
  "type": "field",
  "inboundTag": ["$port"],
  "network": "$network_type",
  "outboundTag": "$socks5_tag"
}
EOL
            
            # 添加路由规则
            jq '.routing.rules += [input]' "$temp_config" "$temp_config.rule" > "$temp_config.new"
            mv "$temp_config.new" "$temp_config"
        fi
    done
    
    # 应用新配置
    cp "$temp_config" "$CONFIG_FILE"
    chmod 644 "$CONFIG_FILE"
    
    # 清理临时文件
    rm -f "$temp_config" "$temp_config.inbound" "$temp_config.socks5" "$temp_config.rule" 2>/dev/null
}

# 显示所有端口配置
list_port_configurations() {
    echo
    echo -e "$yellow 当前所有端口配置 $none"
    echo "----------------------------------------------------------------"
    
    if [ ! -f "$PORT_INFO_FILE" ] || [ ! -s "$PORT_INFO_FILE" ]; then
        echo -e "$red 目前没有配置任何端口，请先添加端口配置 $none"
        return
    fi
    
    echo -e "${cyan}序号   端口    UUID    域名    代理状态${none}"
    echo "----------------------------------------------------------------"
    
    local index=1
    while read -r line; do
        port=$(echo "$line" | cut -d: -f1)
        uuid=$(echo "$line" | cut -d: -f2)
        # 截取UUID的开头和结尾部分，中间用省略号
        uuid_short="${uuid:0:8}...${uuid:24}"
        domain=$(echo "$line" | cut -d: -f6)
        socks5_enabled=$(echo "$line" | cut -d: -f7)
        
        if [[ "$socks5_enabled" == "y" ]]; then
            socks5_status="启用"
        else
            socks5_status="禁用"
        fi
        
        echo -e "${green}$index${none}    ${cyan}$port${none}    ${yellow}$uuid_short${none}    ${magenta}$domain${none}    ${cyan}$socks5_status${none}"
        index=$((index+1))
    done < "$PORT_INFO_FILE"
    
    echo "----------------------------------------------------------------"
}

# 添加新端口配置
add_port_configuration() {
    echo
    echo -e "$yellow 添加新端口配置 $none"
    echo "----------------------------------------------------------------"
    
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
    
    # 生成链接
    if [[ $netstack = "6" ]]; then
        ip="[$ip]"
    fi
    
    vless_reality_url="vless://${uuid}@${ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=random&pbk=${public_key}&sid=${shortid}&#VLESS_R_${ip}_${port}"
    
    echo
    echo "---------- VLESS Reality URL ----------"
    echo -e "${cyan}${vless_reality_url}${none}"
    echo
    
    # 生成二维码
    echo "二维码:"
    qrencode -t UTF8 "$vless_reality_url"
    
    # 保存信息到文件
    echo "$vless_reality_url" > "$HOME/_vless_reality_url_${port}_"
    qrencode -t UTF8 "$vless_reality_url" >> "$HOME/_vless_reality_url_${port}_"
    
    echo
    echo "链接信息已保存到 $HOME/_vless_reality_url_${port}_"
}

# 修改端口配置
modify_port_configuration() {
    echo
    echo -e "$yellow 修改端口配置 $none"
    echo "----------------------------------------------------------------"
    
    if [ ! -f "$PORT_INFO_FILE" ] || [ ! -s "$PORT_INFO_FILE" ]; then
        echo -e "$red 目前没有配置任何端口，请先添加端口配置 $none"
        return
    fi
    
    # 显示所有端口
    list_port_configurations
    
    # 选择要修改的端口
    local port_count=$(wc -l < "$PORT_INFO_FILE")
    while :; do
        read -p "$(echo -e "请选择要修改的配置序号 [${green}1-$port_count${none}]: ")" port_index
        
        if [[ -z "$port_index" ]] || ! [[ "$port_index" =~ ^[0-9]+$ ]] || [[ "$port_index" -lt 1 ]] || [[ "$port_index" -gt "$port_count" ]]; then
            error
            continue
        fi
        
        # 获取对应的端口信息
        selected_port_info=$(sed -n "${port_index}p" "$PORT_INFO_FILE")
        port=$(echo "$selected_port_info" | cut -d: -f1)
        old_uuid=$(echo "$selected_port_info" | cut -d: -f2)
        old_private_key=$(echo "$selected_port_info" | cut -d: -f3)
        old_public_key=$(echo "$selected_port_info" | cut -d: -f4)
        old_shortid=$(echo "$selected_port_info" | cut -d: -f5)
        old_domain=$(echo "$selected_port_info" | cut -d: -f6)
        old_socks5_enabled=$(echo "$selected_port_info" | cut -d: -f7)
        old_socks5_info=$(echo "$selected_port_info" | cut -d: -f8)
        
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
    echo -e "  ${green}5.${none} 返回上一级菜单"
    echo "----------------------------------------------------------------"
    
    read -p "$(echo -e "请选择 [${green}1-5${none}]: ")" modify_choice
    
    case $modify_choice in
        1)
            # 修改UUID
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
                private_key=$(echo -n ${new_uuid} | md5sum | head -c 32 | base64 -w 0 | tr '+/' '-_' | tr -d '=')
                tmp_key=$(echo -n ${private_key} | xargs xray x25519 -i)
                private_key=$(echo ${tmp_key} | awk '{print $3}')
                public_key=$(echo ${tmp_key} | awk '{print $6}')
                
                # 生成新的ShortID
                local new_shortid=$(echo -n ${new_uuid} | sha1sum | head -c 16)
                
                echo
                echo -e "$yellow 新UUID = ${cyan}$new_uuid${none}"
                echo -e "$yellow 新私钥 = ${cyan}$private_key${none}"
                echo -e "$yellow 新公钥 = ${cyan}$public_key${none}"
                echo -e "$yellow 新ShortID = ${cyan}$new_shortid${none}"
                echo
                
                # 保存修改
                save_port_info "$port" "$new_uuid" "$private_key" "$public_key" "$new_shortid" "$old_domain" "$old_socks5_enabled" "$old_socks5_info"
                
                success "UUID修改成功!"
                break
            done
            ;;
            
        2)
            # 修改域名
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
            save_port_info "$port" "$old_uuid" "$old_private_key" "$old_public_key" "$old_shortid" "$new_domain" "$old_socks5_enabled" "$old_socks5_info"
            
            success "域名修改成功!"
            ;;
            
        3)
            # 修改ShortID
            echo
            echo -e "$yellow 修改ShortID $none"
            echo "----------------------------------------------------------------"
            echo -e "当前ShortID: $cyan$old_shortid$none"
            
            # 生成默认ShortID
            local default_shortid=$(echo -n ${old_uuid} | sha1sum | head -c 16)
            
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
                save_port_info "$port" "$old_uuid" "$old_private_key" "$old_public_key" "$new_shortid" "$old_domain" "$old_socks5_enabled" "$old_socks5_info"
                
                success "ShortID修改成功!"
                break
            done
            ;;
            
        4)
            # 修改SOCKS5代理设置
            echo
            echo -e "$yellow 修改SOCKS5代理设置 $none"
            echo "----------------------------------------------------------------"
            
            if [[ "$old_socks5_enabled" == "y" ]]; then
                echo -e "当前状态: ${green}已启用${none}"
                IFS='|' read -r old_socks5_address old_socks5_port old_auth_needed old_socks5_user old_socks5_pass old_udp_over_tcp <<< "$old_socks5_info"
                
                echo -e "SOCKS5服务器: $cyan$old_socks5_address:$old_socks5_port$none"
                if [[ "$old_auth_needed" == "y" ]]; then
                    echo -e "认证: ${green}启用${none} (用户名: $cyan$old_socks5_user$none)"
                else
                    echo -e "认证: ${red}禁用${none}"
                fi
                
                if [[ "$old_udp_over_tcp" == "y" ]]; then
                    echo -e "UDP over TCP: ${green}启用${none}"
                else
                    echo -e "UDP over TCP: ${red}禁用${none}"
                fi
                
                echo
                echo -e "是否要${red}禁用${none} SOCKS5代理?"
                read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" disable_socks5
                
                if [[ "$disable_socks5" == "y" ]]; then
                    # 禁用SOCKS5
                    save_port_info "$port" "$old_uuid" "$old_private_key" "$old_public_key" "$old_shortid" "$old_domain" "n" ""
                    success "SOCKS5代理已禁用!"
                else
                    # 修改SOCKS5设置
                    echo
                    echo -e "请输入新的SOCKS5服务器地址 (当前: $cyan$old_socks5_address$none)"
                    read -p "$(echo -e "(留空保持不变): ")" new_socks5_address
                    [ -z "$new_socks5_address" ] && new_socks5_address=$old_socks5_address
                    
                    echo -e "请输入新的SOCKS5端口 (当前: $cyan$old_socks5_port$none)"
                    read -p "$(echo -e "(留空保持不变): ")" new_socks5_port
                    [ -z "$new_socks5_port" ] && new_socks5_port=$old_socks5_port
                    
                    echo -e "是否需要用户名密码认证? (当前: $cyan$([ "$old_auth_needed" == "y" ] && echo "是" || echo "否")$none)"
                    read -p "$(echo -e "(y/n, 默认: ${cyan}$old_auth_needed${none}): ")" new_auth_needed
                    [ -z "$new_auth_needed" ] && new_auth_needed=$old_auth_needed
                    
                    new_socks5_user=$old_socks5_user
                    new_socks5_pass=$old_socks5_pass
                    if [[ "$new_auth_needed" == "y" ]]; then
                        echo -e "请输入用户名 (当前: $cyan$old_socks5_user$none)"
                        read -p "$(echo -e "(留空保持不变): ")" temp_user
                        [ -n "$temp_user" ] && new_socks5_user=$temp_user
                        
                        echo -e "请输入密码 (当前: $cyan$old_socks5_pass$none)"
                        read -p "$(echo -e "(留空保持不变): ")" temp_pass
                        [ -n "$temp_pass" ] && new_socks5_pass=$temp_pass
                    fi
                    
                    echo -e "是否启用UDP over TCP? (当前: $cyan$([ "$old_udp_over_tcp" == "y" ] && echo "是" || echo "否")$none)"
                    read -p "$(echo -e "(y/n, 默认: ${cyan}$old_udp_over_tcp${none}): ")" new_udp_over_tcp
                    [ -z "$new_udp_over_tcp" ] && new_udp_over_tcp=$old_udp_over_tcp
                    
                    # 格式化新的SOCKS5信息
                    new_socks5_info="${new_socks5_address}|${new_socks5_port}|${new_auth_needed}|${new_socks5_user}|${new_socks5_pass}|${new_udp_over_tcp}"
                    
                    # 保存修改
                    save_port_info "$port" "$old_uuid" "$old_private_key" "$old_public_key" "$old_shortid" "$old_domain" "y" "$new_socks5_info"
                    
                    success "SOCKS5代理设置已更新!"
                fi
            else
                echo -e "当前状态: ${red}未启用${none}"
                echo
                echo -e "是否要${green}启用${none} SOCKS5代理?"
                read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" enable_socks5
                
                if [[ "$enable_socks5" == "y" ]]; then
                    # 启用SOCKS5
                    # SOCKS5 服务器地址
                    read -p "$(echo -e "请输入 SOCKS5 服务器地址: ")" socks5_address
                    if [ -z "$socks5_address" ]; then
                        error
                        return
                    fi
                    
                    # SOCKS5 端口
                    read -p "$(echo -e "请输入 SOCKS5 端口: ")" socks5_port
                    if [ -z "$socks5_port" ] || ! [[ "$socks5_port" =~ ^[0-9]+$ ]]; then
                        error
                        return
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
                    fi
                    
                    # 是否启用 UDP over TCP
                    echo -e "是否启用 UDP over TCP?"
                    read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" udp_over_tcp
                    [ -z "$udp_over_tcp" ] && udp_over_tcp="n"
                    
                    if [[ $udp_over_tcp = "n" ]]; then
                        echo -e "$yellow 注意：未启用 UDP over TCP，仅进行 TCP 转发 $none"
                    fi
                    
                    # 格式化SOCKS5信息
                    new_socks5_info="${socks5_address}|${socks5_port}|${auth_needed}|${socks5_user}|${socks5_pass}|${udp_over_tcp}"
                    
                    # 保存修改
                    save_port_info "$port" "$old_uuid" "$old_private_key" "$old_public_key" "$old_shortid" "$old_domain" "y" "$new_socks5_info"
                    
                    success "SOCKS5代理已启用!"
                fi
            fi
            ;;
            
        5)
            return
            ;;
            
        *)
            error
            return
            ;;
    esac
    
    # 更新配置文件
    update_config_file
    
    # 重启 Xray
    echo
    echo -e "$yellow 重启 Xray 服务... $none"
    if systemctl restart xray; then
        echo -e "$green Xray 服务重启成功! $none"
    else
        echo -e "$red Xray 服务重启失败，请手动检查! $none"
    fi
    
    # 为修改后的端口生成新的连接信息
    local ip=$([ "$netstack" = "6" ] && echo "$IPv6" || echo "$IPv4")
    generate_connection_info "$port" "$(get_port_info $port | cut -d: -f2)" "$(get_port_info $port | cut -d: -f4)" "$(get_port_info $port | cut -d: -f5)" "$(get_port_info $port | cut -d: -f6)" "$ip" "$netstack"
    
    pause
}

# 删除端口配置
delete_port_configuration() {
    echo
    echo -e "$yellow 删除端口配置 $none"
    echo "----------------------------------------------------------------"
    
    if [ ! -f "$PORT_INFO_FILE" ] || [ ! -s "$PORT_INFO_FILE" ]; then
        echo -e "$red 目前没有配置任何端口，请先添加端口配置 $none"
        return
    fi
    
    # 显示所有端口
    list_port_configurations
    
    # 选择要删除的端口
    local port_count=$(wc -l < "$PORT_INFO_FILE")
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
        selected_port_info=$(sed -n "${port_index}p" "$PORT_INFO_FILE")
        port=$(echo "$selected_port_info" | cut -d: -f1)
        
        echo
        echo -e "$yellow 确认要删除端口 ${cyan}$port${none} 的配置吗? $none"
        read -p "$(echo -e "(y/n, 默认: ${cyan}n${none}): ")" confirm_delete
        
        if [[ "$confirm_delete" == "y" ]]; then
            # 删除端口信息
            delete_port_info "$port"
            
            # 更新配置文件
            update_config_file
            
            # 重启 Xray
            echo
            echo -e "$yellow 重启 Xray 服务... $none"
            if systemctl restart xray; then
                echo -e "$green Xray 服务重启成功! $none"
            else
                echo -e "$red Xray 服务重启失败，请手动检查! $none"
            fi
            
            success "端口 $port 配置已删除!"
        else
            echo -e "$yellow 操作已取消 $none"
        fi
        
        break
    done
    
    pause
}

# 显示所有端口的连接信息
show_all_connections() {
    echo
    echo -e "$yellow 所有端口的连接信息 $none"
    echo "----------------------------------------------------------------"
    
    if [ ! -f "$PORT_INFO_FILE" ] || [ ! -s "$PORT_INFO_FILE" ]; then
        echo -e "$red 目前没有配置任何端口，请先添加端口配置 $none"
        return
    fi
    
    # 获取本机IP
    if ! get_local_ips; then
        echo -e "${red}获取IP地址失败!${none}"
        return
    fi
    
    while read -r line; do
        port=$(echo "$line" | cut -d: -f1)
        uuid=$(echo "$line" | cut -d: -f2)
        public_key=$(echo "$line" | cut -d: -f4)
        shortid=$(echo "$line" | cut -d: -f5)
        domain=$(echo "$line" | cut -d: -f6)
        
        # 根据当前网络环境选择IP
        if [[ -n "$IPv4" ]]; then
            ip=$IPv4
            netstack=4
        elif [[ -n "$IPv6" ]]; then
            ip=$IPv6
            netstack=6
        fi
        
        generate_connection_info "$port" "$uuid" "$public_key" "$shortid" "$domain" "$ip" "$netstack"
    done < "$PORT_INFO_FILE"
    
    pause
}

# 安装 Xray 的主函数
install_xray() {
    # 说明
    echo
    echo -e "$yellow此脚本仅兼容于Debian 10+系统. 如果你的系统不符合,请Ctrl+C退出脚本$none"
    echo -e "可以去 ${cyan}https://github.com/crazypeace/xray-vless-reality${none} 查看脚本整体思路和关键命令, 以便针对你自己的系统做出调整."
    echo -e "有问题加群 ${cyan}https://t.me/+ISuvkzFGZPBhMzE1${none}"
    echo "----------------------------------------------------------------"

    # 准备工作
    apt update
    apt install -y curl sudo jq qrencode net-tools lsof

    # Xray官方脚本安装最新版本
    echo
    echo -e "${yellow}Xray官方脚本安装最新版本$none"
    echo "----------------------------------------------------------------"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

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
    
    # 提示用户添加端口
    echo
    echo -e "$green Xray 安装完成！$none"
    echo -e "$yellow 接下来您需要添加端口配置 $none"
    pause
    
    # 添加第一个端口配置
    add_port_configuration
}

# 卸载Xray
uninstall_xray() {
    echo
    echo -e "$yellow 卸载 Xray $none"
    echo "----------------------------------------------------------------"
    
    echo -e "$red 警告：此操作将完全卸载 Xray 及其所有配置！$none"
    echo -e "这将删除："
    echo -e "1. Xray 程序及其服务"
    echo -e "2. 所有端口配置信息"
    echo -e "3. 所有连接配置文件"
    echo
    
    read -p "$(echo -e "确定要卸载吗？请输入 ${red}uninstall${none} 以确认: ")" confirm
    
    if [[ "$confirm" != "uninstall" ]]; then
        echo -e "$yellow 操作已取消 $none"
        return
    fi
    
    # 停止并禁用Xray服务
    echo -e "$yellow 停止并禁用 Xray 服务... $none"
    systemctl stop xray
    systemctl disable xray
    
    # 卸载Xray
    echo -e "$yellow 卸载 Xray... $none"
    if bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge; then
        echo -e "$green Xray 已成功卸载 $none"
    else
        echo -e "$red Xray 卸载失败，请手动检查 $none"
    fi
    
    # 删除所有配置信息
    echo -e "$yellow 删除配置信息... $none"
    rm -f "$PORT_INFO_FILE"
    rm -f "$HOME/_vless_reality_url_*"
    
    # 清除任何残留文件
    rm -rf /usr/local/etc/xray
    rm -rf /usr/local/share/xray
    rm -rf /var/log/xray
    
    echo
    echo -e "$green Xray 及其所有配置已成功删除！$none"
    pause
}

# 主菜单
show_menu() {
    echo
    echo "---------- Xray 多端口管理脚本 -------------"
    echo -e "  ${green}1.${none} 安装/重装 Xray"
    echo -e "  ${green}2.${none} 添加新端口配置"
    echo -e "  ${green}3.${none} 查看所有端口配置"
    echo -e "  ${green}4.${none} 修改端口配置"
    echo -e "  ${green}5.${none} 删除端口配置"
    echo -e "  ${green}6.${none} 显示所有端口连接信息"
    echo -e "  ${green}7.${none} 更新 GeoIP 和 GeoSite 数据"
    echo -e "  ${green}8.${none} 卸载 Xray 及所有配置"
    echo -e "  ${green}0.${none} 退出"
    echo "------------------------------------"
    read -p "请选择 [0-8]: " choice

    case $choice in
        1)
            install_xray
            show_menu
            ;;
        2)
            add_port_configuration
            show_menu
            ;;
        3)
            list_port_configurations
            pause
            show_menu
            ;;
        4)
            modify_port_configuration
            show_menu
            ;;
        5)
            delete_port_configuration
            show_menu
            ;;
        6)
            show_all_connections
            show_menu
            ;;
        7)
            update_geodata
            show_menu
            ;;
        8)
            uninstall_xray
            show_menu
            ;;
        0)
            exit 0
            ;;
        *)
            error
            show_menu
            ;;
    esac
}

# 如果没有带参数运行，显示菜单
if [ $# -eq 0 ]; then
    show_menu
else
    # 如果带参数运行，直接安装
    install_xray "$@"
fi
