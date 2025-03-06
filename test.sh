#!/bin/bash

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
  echo "请使用root权限运行此脚本"
  exit 1
fi

# 检查是否安装了nginx
if ! command -v nginx &>/dev/null; then
  echo "未检测到Nginx，是否安装? (y/n)"
  read install_nginx
  if [ "$install_nginx" == "y" ] || [ "$install_nginx" == "Y" ]; then
    # 检测系统类型
    if command -v apt &>/dev/null; then
      apt update
      apt install -y nginx
    elif command -v yum &>/dev/null; then
      yum install -y epel-release
      yum install -y nginx
    else
      echo "无法确定系统类型，请手动安装Nginx后再运行此脚本"
      exit 1
    fi
    echo "Nginx安装完成"
  else
    echo "未安装Nginx，退出脚本"
    exit 1
  fi
fi

# 获取用户输入
echo "请输入域名 (例如: example.com):"
read domain_name

echo "请输入后端服务端口 (例如: 19304):"
read backend_port

echo "请输入子路径 (例如: /abc123，如果没有请留空):"
read sub_path

# 如果子路径为空，设置为默认值
if [ -z "$sub_path" ]; then
  echo "未提供子路径，只配置根路径代理"
  has_sub_path=false
else
  # 确保子路径以/开头
  if [[ $sub_path != /* ]]; then
    sub_path="/$sub_path"
  fi
  has_sub_path=true
fi

# 创建证书目录
cert_dir="/root/cert/$domain_name"
if [ ! -d "$cert_dir" ]; then
  mkdir -p "$cert_dir"
  echo "证书目录已创建: $cert_dir"
  echo "请确保将SSL证书放置于以下位置:"
  echo "  - 完整证书链: $cert_dir/fullchain.pem"
  echo "  - 私钥: $cert_dir/privkey.pem"
fi

# 生成Nginx配置文件
config_file="/etc/nginx/conf.d/$domain_name.conf"

cat > "$config_file" << EOF
server {
    listen 80;
    server_name $domain_name;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $domain_name;
    
    ssl_certificate $cert_dir/fullchain.pem;
    ssl_certificate_key $cert_dir/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;
    
    # 更智能的处理客户端IP
    set \$real_ip \$remote_addr;
    if (\$http_cf_connecting_ip) {
        set \$real_ip \$http_cf_connecting_ip;
    }
    
EOF

# 如果有子路径，添加子路径配置
if [ "$has_sub_path" = true ]; then
cat >> "$config_file" << EOF
    location $sub_path {
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$real_ip;
        proxy_redirect off;
        proxy_pass https://127.0.0.1:$backend_port$sub_path;
        proxy_ssl_verify off;
    }
    
EOF
fi

# 添加根路径配置
cat >> "$config_file" << EOF
    location / {
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$real_ip;
        proxy_redirect off;
        proxy_pass https://127.0.0.1:$backend_port;
        proxy_ssl_verify off;
        
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
    }
}
EOF

echo "配置文件已生成: $config_file"

# 检查nginx配置
echo "正在检查Nginx配置..."
nginx -t

if [ $? -eq 0 ]; then
  echo "配置检查通过，是否重新加载Nginx? (y/n)"
  read reload_nginx
  if [ "$reload_nginx" == "y" ] || [ "$reload_nginx" == "Y" ]; then
    systemctl reload nginx
    echo "Nginx已重新加载"
  else
    echo "跳过Nginx重新加载，您可以稍后手动执行: systemctl reload nginx"
  fi
else
  echo "Nginx配置检查失败，请修复错误后再重新加载"
fi

echo "脚本执行完毕"
