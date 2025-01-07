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

pause() {
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

# 主菜单
show_menu() {
    echo
    echo "---------- Xray 管理脚本 -------------"
    echo -e "  ${green}1.${none} 安装/重装 Xray"
    echo -e "  ${green}2.${none} 更新 GeoIP 和 GeoSite 数据"
    echo -e "  ${green}0.${none} 退出"
    echo "------------------------------------"
    read -p "请选择 [0-2]: " choice

    case $choice in
        1)
            install_xray
            ;;
        2)
            update_geodata
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

# 安装 Xray 的主函数
install_xray() {
    # 说明
    echo
    echo -e "$yellow此脚本仅兼容于Debian 10+系统. 如果你的系统不符合,请Ctrl+C退出脚本$none"
    echo -e "可以去 ${cyan}https://github.com/crazypeace/xray-vless-reality${none} 查看脚本整体思路和关键命令, 以便针对你自己的系统做出调整."
    echo -e "有问题加群 ${cyan}https://t.me/+ISuvkzFGZPBhMzE1${none}"
    echo -e "本脚本支持带参数执行, 省略交互过程, 详见GitHub."
    echo "----------------------------------------------------------------"

    # 获取本机IP
    echo -e "$yellow获取本机IP地址...${none}"
    if ! get_local_ips; then
        echo -e "${red}获取IP地址失败!${none}"
        echo -e "是否继续安装?[y/N]"
        read -r continue_install
        if [[ ! $continue_install =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi

    # 生成UUID
    uuidSeed=${IPv4}${IPv6}$(cat /proc/sys/kernel/hostname)$(cat /etc/timezone)
    default_uuid=$(curl -sL https://www.uuidtools.com/api/generate/v3/namespace/ns:dns/name/${uuidSeed} | grep -oP '[^-]{8}-[^-]{4}-[^-]{4}-[^-]{4}-[^-]{12}')

    # 执行脚本带参数
    if [ $# -ge 1 ]; then
        case ${1} in
            4)
                netstack=4
                ip=${IPv4}
                ;;
            6)
                netstack=6
                ip=${IPv6}
                ;;
            *)
                if [[ -n "$IPv4" ]]; then
                    netstack=4
                    ip=${IPv4}
                elif [[ -n "$IPv6" ]]; then
                    netstack=6
                    ip=${IPv6}
                else
                    warn "没有获取到公共IP"
                fi
                ;;
        esac

        port=${2:-443}
        domain=${3:-"learn.microsoft.com"}
        uuid=${4:-$default_uuid}

        echo -e "$yellow netstack = ${cyan}${netstack}${none}"
        echo -e "$yellow 本机IP = ${cyan}${ip}${none}"
        echo -e "$yellow 端口 (Port) = ${cyan}${port}${none}"
        echo -e "$yellow 用户ID (User ID / UUID) = $cyan${uuid}${none}"
        echo -e "$yellow SNI = ${cyan}$domain${none}"
        echo "----------------------------------------------------------------"
    fi

    pause

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

    # 如果脚本带参数执行的, 要在安装了xray之后再生成默认私钥公钥shortID
    if [[ -n $uuid ]]; then
        private_key=$(echo -n ${uuid} | md5sum | head -c 32 | base64 -w 0 | tr '+/' '-_' | tr -d '=')
        tmp_key=$(echo -n ${private_key} | xargs xray x25519 -i)
        private_key=$(echo ${tmp_key} | awk '{print $3}')
        public_key=$(echo ${tmp_key} | awk '{print $6}')
        shortid=$(echo -n ${uuid} | sha1sum | head -c 16)
        
        echo
        echo "私钥公钥要在安装xray之后才可以生成"
        echo -e "$yellow 私钥 (PrivateKey) = ${cyan}${private_key}${none}"
        echo -e "$yellow 公钥 (PublicKey) = ${cyan}${public_key}${none}"
        echo -e "$yellow ShortId = ${cyan}${shortid}${none}"
        echo "----------------------------------------------------------------"
    fi

    # 打开BBR
    echo
    echo -e "$yellow打开BBR$none"
    echo "----------------------------------------------------------------"
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.conf
    echo "net.core.default_qdisc = fq" >>/etc/sysctl.conf
    sysctl -p >/dev/null 2>&1

    # 配置 VLESS_Reality 模式
    echo
    echo -e "$yellow配置 VLESS_Reality 模式$none"
    echo "----------------------------------------------------------------"

    # 网络栈
    if [[ -z $netstack ]]; then
        echo
        echo -e "如果你的小鸡是${magenta}双栈(同时有IPv4和IPv6的IP)${none}，请选择你把Xray搭在哪个'网口'上"
        echo "如果你不懂这段话是什么意思, 请直接回车"
        read -p "$(echo -e "Input ${cyan}4${none} for IPv4, ${cyan}6${none} for IPv6:") " netstack

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
    fi

    # 端口
    if [[ -z $port ]]; then
        default_port=443
        while :; do
            read -p "$(echo -e "请输入端口 [${magenta}1-65535${none}] Input port (默认Default ${cyan}${default_port}$none):")" port
            [ -z "$port" ] && port=$default_port
            case $port in
                [1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]|[1-5][0-9][0-9][0-9][0-9]|6[0-4][0-9][0-9][0-9]|65[0-4][0-9][0-9]|655[0-3][0-5])
                    echo
                    echo
                    echo -e "$yellow 端口 (Port) = ${cyan}${port}${none}"
                    echo "----------------------------------------------------------------"
                    echo
                    break
                    ;;
                *)
                    error
                    ;;
            esac
        done
    fi

    # UUID
    if [[ -z $uuid ]]; then
        while :; do
            echo -e "请输入 "$yellow"UUID"$none" "
            read -p "$(echo -e "(默认ID: ${cyan}${default_uuid}$none):")" uuid
            [ -z "$uuid" ] && uuid=$default_uuid
            case $(echo -n $uuid | sed -E 's/[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}//g') in
                "")
                    echo
                    echo
                    echo -e "$yellow UUID = $cyan$uuid$none"
                    echo "----------------------------------------------------------------"
                    echo
                    break
                    ;;
                *)
                    error
                    ;;
            esac
        done
    fi

    # x25519公私钥
    if [[ -z $private_key ]]; then
        private_key=$(echo -n ${uuid} | md5sum | head -c 32 | base64 -w 0 | tr '+/' '-_' | tr -d '=')
        tmp_key=$(echo -n ${private_key} | xargs xray x25519 -i)
        default_private_key=$(echo ${tmp_key} | awk '{print $3}')
        default_public_key=$(echo ${tmp_key} | awk '{print $6}')

        echo -e "请输入 "$yellow"x25519 Private Key"$none" x25519私钥 :"
        read -p "$(echo -e "(默认私钥 Private Key: ${cyan}${default_private_key}$none):")" private_key
        if [[ -z "$private_key" ]]; then 
            private_key=$default_private_key
            public_key=$default_public_key
        else
            tmp_key=$(echo -n ${private_key} | xargs xray x25519 -i)
            private_key=$(echo ${tmp_key} | awk '{print $3}')
            public_key=$(echo ${tmp_key} | awk '{print $6}')
        fi

        echo
        echo 
        echo -e "$yellow 私钥 (PrivateKey) = ${cyan}${private_key}$none"
        echo -e "$yellow 公钥 (PublicKey) = ${cyan}${public_key}$none"
        echo "----------------------------------------------------------------"
        echo
    fi

    # ShortID
    if [[ -z $shortid ]]; then
        default_shortid=$(echo -n ${uuid} | sha1sum | head -c 16)
        while :; do
            echo -e "请输入 "$yellow"ShortID"$none" :"
            read -p "$(echo -e "(默认ShortID: ${cyan}${default_shortid}$none):")" shortid
            [ -z "$shortid" ] && shortid=$default_shortid
            if [[ ${#shortid} -gt 16 ]]; then
                error
                continue
            elif [[ $(( ${#shortid} % 2 )) -ne 0 ]]; then
                error
                continue
            else
                echo
                echo
                echo -e "$yellow ShortID = ${cyan}${shortid}$none"
                echo "----------------------------------------------------------------"
                echo
                break
            fi
        done
    fi

    # 目标网站
    if [[ -z $domain ]]; then
        echo -e "请输入一个 ${magenta}合适的域名${none} Input the domain"
        read -p "(例如: learn.microsoft.com): " domain
        [ -z "$domain" ] && domain="learn.microsoft.com"

        echo
        echo
        echo -e "$yellow SNI = ${cyan}$domain$none"
        echo "----------------------------------------------------------------"
        echo
    fi

    # SOCKS5 代理设置
    echo
    echo -e "$yellow 是否配置 SOCKS5 转发代理? $none"
    read -p "$(echo -e "(y/n, 默认: ${cyan}n$none):")" socks5_enabled
    [ -z "$socks5_enabled" ] && socks5_enabled="n"

    if [[ $socks5_enabled = "y" ]]; then
        # SOCKS5 服务器地址
        read -p "$(echo -e "请输入 SOCKS5 服务器地址: ")" socks5_address
        [ -z "$socks5_address" ] && error && exit 1

        # SOCKS5 端口
        read -p "$(echo -e "请输入 SOCKS5 端口: ")" socks5_port
        [ -z "$socks5_port" ] && error && exit 1

        # 是否需要认证
        echo -e "是否需要用户名密码认证?"
        read -p "$(echo -e "(y/n, 默认: ${cyan}n$none):")" auth_needed
        [ -z "$auth_needed" ] && auth_needed="n"

        if [[ $auth_needed = "y" ]]; then
            read -p "$(echo -e "请输入用户名: ")" socks5_user
            read -p "$(echo -e "请输入密码: ")" socks5_pass
        fi

        # 是否启用 UDP over TCP
        echo -e "是否启用 UDP over TCP?"
        read -p "$(echo -e "(y/n, 默认: ${cyan}n$none):")" udp_over_tcp
        [ -z "$udp_over_tcp" ] && udp_over_tcp="n"

        if [[ $udp_over_tcp = "n" ]]; then
            echo -e "$yellow 注意：未启用 UDP over TCP，仅进行 TCP 转发 $none"
        fi
    fi
    
    # 配置config.json
    echo
    echo -e "$yellow 配置 /usr/local/etc/xray/config.json $none"
    echo "----------------------------------------------------------------"

    # 首先创建一个临时文件来存储SOCKS5配置（如果启用）
    if [[ $socks5_enabled = "y" ]]; then
        socks5_config=',
    {
      "protocol": "socks",
      "settings": {
        "servers": [
          {
            "address": "'$socks5_address'",
            "port": '$socks5_port
        if [[ $auth_needed = "y" ]]; then
            socks5_config+=',"users": [{"user": "'$socks5_user'","pass": "'$socks5_pass'"}]'
        fi
        socks5_config+='}]}'
        
        if [[ $udp_over_tcp = "y" ]]; then
            socks5_config+=',"streamSettings": {"sockopt": {"udpFragmentSize": 1400,"tcpFastOpen": true,"tcpKeepAliveInterval": 15}},"transportLayer": true'
        fi
        socks5_config+=',"tag": "socks5-out"}'

        socks5_routing=',
      {
        "type": "field",
        "network": "'$([ "$udp_over_tcp" = "y" ] && echo "tcp,udp" || echo "tcp")'",
        "outboundTag": "socks5-out"
      }'
    else
        socks5_config=""
        socks5_routing=""
    fi

    # 生成config.json
    cat > /usr/local/etc/xray/config.json << EOL
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": [
      "8.8.8.8",
      "8.8.4.4",
      "localhost"
    ],
    "queryStrategy": "UseIPv4"
  },
  "inbounds": [
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
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct",
      "settings": {
        "domainStrategy": "UseIP"
      }
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }${socks5_config}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      }${socks5_routing}
    ]
  }
}
EOL

    # 重启 Xray
    echo
    echo -e "$yellow重启 Xray$none"
    echo "----------------------------------------------------------------"
    service xray restart

    # 指纹FingerPrint
    fingerprint="random"

    # SpiderX
    spiderx=""

    echo
    echo "---------- Xray 配置信息 -------------"
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
    echo -e "$yellow 指纹 (Fingerprint) = ${cyan}${fingerprint}$none"
    echo -e "$yellow 公钥 (PublicKey) = ${cyan}${public_key}$none"
    echo -e "$yellow ShortId = ${cyan}${shortid}$none"
    echo -e "$yellow SpiderX = ${cyan}${spiderx}$none"

    if [[ $socks5_enabled = "y" ]]; then
        echo
        echo "---------- SOCKS5 代理配置 -------------"
        echo -e "$yellow SOCKS5 服务器 = ${cyan}${socks5_address}:${socks5_port}${none}"
        if [[ $auth_needed = "y" ]]; then
            echo -e "$yellow 用户名 = ${cyan}${socks5_user}${none}"
            echo -e "$yellow 密码 = ${cyan}${socks5_pass}${none}"
        fi
        echo -e "$yellow UDP over TCP = ${cyan}$([ $udp_over_tcp = "y" ] && echo "已启用" || echo "未启用")${none}"
    fi

    echo
    echo "---------- VLESS Reality URL ----------"
    if [[ $netstack = "6" ]]; then
      ip=[$ip]
    fi
    vless_reality_url="vless://${uuid}@${ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=${fingerprint}&pbk=${public_key}&sid=${shortid}&spx=${spiderx}&#VLESS_R_${ip}"
    echo -e "${cyan}${vless_reality_url}${none}"
    echo
    sleep 3
    echo "以下两个二维码完全一样的内容"
    qrencode -t UTF8 $vless_reality_url
    qrencode -t ANSI $vless_reality_url
    echo
    echo "---------- END -------------"
    echo "节点信息保存在 ~/_vless_reality_url_ 中"

    # 保存配置信息到文件
    echo $vless_reality_url > ~/_vless_reality_url_
    echo "以下两个二维码完全一样的内容" >> ~/_vless_reality_url_
    qrencode -t UTF8 $vless_reality_url >> ~/_vless_reality_url_
    qrencode -t ANSI $vless_reality_url >> ~/_vless_reality_url_
}

# 如果没有带参数运行，显示菜单
if [ $# -eq 0 ]; then
    show_menu
else
    # 如果带参数运行，直接安装
    install_xray "$@"
fi
