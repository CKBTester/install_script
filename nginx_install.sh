#!/bin/bash

# ==================== 错误处理配置 ====================
# 错误处理函数
handle_error() {
    local line=$1
    local code=$2
    local cmd=$3
    local exit_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo -e "\n${RED}========================================${NC}"
    echo -e "${RED}[ERROR] 脚本在 $exit_time 退出${NC}"
    echo -e "${RED}[ERROR] 出错行号: $line${NC}"
    echo -e "${RED}[ERROR] 错误代码: $code${NC}"
    echo -e "${RED}[ERROR] 失败命令: $cmd${NC}"
    echo -e "${RED}[ERROR] 当前工作目录: $(pwd)${NC}"
    echo -e "${RED}========================================${NC}\n"
    
    exit $code
}

# 设置错误陷阱
trap 'handle_error ${LINENO} $? "$BASH_COMMAND"' ERR

# Set error handling
set -e
set -o pipefail

# Color codes
if [ -t 1 ]; then
  # 终端支持颜色
  RED="\033[0;31m"
  GREEN="\033[0;32m"
  YELLOW="\033[0;33m"
  BLUE="\033[0;34m"
  NC="\033[0m" # No Color
else
  RED=''
  GREEN=''
  YELLOW=''
  BLUE=''
  NC=''
fi

# 记录开始时间
START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}[INFO] 脚本开始执行: $START_TIME${NC}"
echo -e "${BLUE}========================================${NC}"

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root. Use sudo.${NC}"
   exit 1
fi

# Update and upgrade system packages
echo -e "${YELLOW}[1/12] 更新 system packages...${NC}"
apt update && apt upgrade -y && apt dist-upgrade -y && apt full-upgrade -y && apt autoremove -y
echo -e "${GREEN}[OK] 系统包更新完成${NC}"

# Install required dependencies
echo -e "${YELLOW}[2/12] 安装相关组件...${NC}"
apt install -y build-essential git cmake libpcre2-dev zlib1g-dev \
               openssl libssl-dev libxml2-dev libxslt1-dev libgd-dev libgeoip-dev \
               libgoogle-perftools-dev libperl-dev perl-base perl
echo -e "${GREEN}[OK] 依赖包安装完成${NC}"

# debian13暂时删除libpcre3 libpcre3-dev，找不到包.

# Create compilation directory
echo -e "${YELLOW}[3/12] 创建编译目录...${NC}"
mkdir -p /home/compile/nginx
export COMPILE_PATH="/home/compile/nginx"
cd $COMPILE_PATH

# 清理旧的编译文件（如果存在）
if [ -d "nginx_src" ]; then
    echo -e "${YELLOW}检测到旧的 nginx_src 目录，正在清理...${NC}"
    rm -rf nginx_src
fi

if [ -d "ngx_brotli" ]; then
    echo -e "${YELLOW}检测到旧的 ngx_brotli 目录，正在清理...${NC}"
    rm -rf ngx_brotli
fi

echo -e "${GREEN}[OK] 编译目录: $COMPILE_PATH${NC}"

# Set Nginx version (optional - leave empty for latest stable)
export NGINX_VERSION="1.30.0"  # 如果想安装最新版，可以改成 NGINX_VERSION=""

# Download and prepare Nginx source
if [ -z "$NGINX_VERSION" ]; then
    # 如果版本号为空，自动获取最新稳定版
    echo -e "${YELLOW}[4/12] 获取最新稳定版 Nginx 版本...${NC}"
    
    download_page=$(curl -s https://nginx.org/en/download.html)
    latest_stable_link=$(echo "$download_page" | grep -oP 'nginx-1\.\d+\.\d+\.tar\.gz' | head -1)
    
    if [ -z "$latest_stable_link" ]; then
        echo -e "${RED}Failed to fetch the latest stable version. Please check your network.${NC}"
        exit 1
    fi
    
    export NGINX_VERSION=$(echo "$latest_stable_link" | grep -oP '1\.\d+\.\d+')
    echo -e "${GREEN}[OK] 检测到最新版本: $NGINX_VERSION${NC}"
    
    # 删除旧的压缩包
    rm -f "nginx-$NGINX_VERSION.tar.gz"
    
    # 下载最新版
    echo -e "${YELLOW}[4/12] 下载 Nginx $NGINX_VERSION...${NC}"
    wget "https://nginx.org/download/$latest_stable_link"
else
    # 使用指定的版本号
    echo -e "${YELLOW}[4/12] 下载 Nginx $NGINX_VERSION (指定版本)...${NC}"
    
    # 删除旧的压缩包
    rm -f "nginx-$NGINX_VERSION.tar.gz"
    
    wget "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
fi

# 检查下载是否成功
if [ ! -f "nginx-$NGINX_VERSION.tar.gz" ]; then
    echo -e "${RED}下载失败！文件不存在。${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Nginx 源码包下载成功${NC}"

# 解压源码包
echo -e "${YELLOW}[5/12] 解压 Nginx 源码包...${NC}"
tar -zxvf "nginx-$NGINX_VERSION.tar.gz"

if [ $? -ne 0 ]; then
    echo -e "${RED}解压失败！压缩包可能已损坏或不存在。${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] 源码包解压成功${NC}"

# 清理压缩包并重命名源码目录
rm -f "nginx-$NGINX_VERSION.tar.gz"

# 如果 nginx_src 目录已存在，先删除
if [ -d "nginx_src" ]; then
    echo -e "${YELLOW}删除已存在的 nginx_src 目录...${NC}"
    rm -rf nginx_src
fi

# 重命名源码目录
mv "nginx-$NGINX_VERSION" nginx_src
echo -e "${GREEN}[OK] Nginx 源码准备完成 (版本: $NGINX_VERSION)${NC}"

# Clone Brotli module
echo -e "${YELLOW}[6/12] 克隆 Brotli 模块...${NC}"

# 如果 ngx_brotli 目录已存在，先删除
if [ -d "ngx_brotli" ]; then
    echo -e "${YELLOW}删除已存在的 ngx_brotli 目录...${NC}"
    rm -rf ngx_brotli
fi

git clone https://github.com/google/ngx_brotli
cd ngx_brotli
git submodule update --init
cd ..
echo -e "${GREEN}[OK] Brotli 模块下载完成${NC}"

# Configure Nginx
cd nginx_src
echo -e "${YELLOW}[7/12] 配置 Nginx...${NC}"
./configure \
--prefix=/etc/nginx \
--sbin-path=/usr/sbin/nginx \
--modules-path=/usr/lib/nginx/modules \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--pid-path=/var/run/nginx.pid \
--lock-path=/var/run/nginx.lock \
--http-client-body-temp-path=/var/cache/nginx/client_temp \
--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
--user=nginx \
--group=nginx \
--with-threads \
--with-file-aio \
--with-http_ssl_module \
--with-http_v2_module \
--with-http_v3_module \
--with-http_realip_module \
--with-http_addition_module \
--with-http_xslt_module \
--with-http_image_filter_module \
--with-http_geoip_module \
--with-http_sub_module \
--with-http_dav_module \
--with-http_flv_module \
--with-http_mp4_module \
--with-http_gunzip_module \
--with-http_gzip_static_module \
--with-http_auth_request_module \
--with-http_random_index_module \
--with-http_secure_link_module \
--with-http_degradation_module \
--with-http_slice_module \
--with-http_stub_status_module \
--with-http_perl_module \
--with-mail \
--with-mail_ssl_module \
--with-stream \
--with-stream_ssl_module \
--with-stream_realip_module \
--with-stream_geoip_module \
--with-stream_ssl_preread_module \
--add-module=$COMPILE_PATH/ngx_brotli \
--with-compat \
--with-cc-opt='-g0 -O3 -fstack-reuse=all -fdwarf2-cfi-asm -fplt -fno-trapv -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-check -fno-stack-clash-protection -fno-stack-protector -fcf-protection=none -fno-split-stack -fno-sanitize=all -fno-instrument-functions'

if [ $? -ne 0 ]; then
    echo -e "${RED}配置失败！${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Nginx 配置成功${NC}"

# Compile Nginx
echo -e "${YELLOW}[8/12] 编译 Nginx (make)...${NC}"
make -j$(nproc)  # 使用多核编译加速

if [ $? -ne 0 ]; then
    echo -e "${RED}编译失败！${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Nginx 编译成功${NC}"

# Install Nginx
echo -e "${YELLOW}[9/12] 安装 Nginx...${NC}"
make install

if [ $? -ne 0 ]; then
    echo -e "${RED}安装失败！${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Nginx 安装成功${NC}"

# Create systemd service file
echo -e "${YELLOW}[10/12] 创建 Nginx systemd service...${NC}"
cat > /etc/systemd/system/nginx.service << 'EOF'
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
Restart=always
RestartSec=15
StartLimitInterval=0
User=root

ExecStartPre=/bin/rm -rf /dev/shm/nginx
ExecStartPre=/bin/mkdir /dev/shm/nginx
ExecStartPre=/bin/chmod 711 /dev/shm/nginx
ExecStartPre=/bin/mkdir /dev/shm/nginx/tcmalloc
ExecStartPre=/bin/chmod 0777 /dev/shm/nginx/tcmalloc

ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s stop
ExecStopPost=/bin/rm -rf /dev/shm/nginx

PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
echo -e "${GREEN}[OK] systemd service 文件创建成功${NC}"

# Backup original nginx.conf and create new configuration
echo -e "${YELLOW}[11/12] 配置 Nginx...${NC}"

# 检查配置文件是否存在
if [ -f /etc/nginx/nginx.conf ]; then
    mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%Y%m%d_%H%M%S)
fi

# Create new nginx.conf
curl -L "https://raw.githubusercontent.com/CKBTester/install_script/main/nginx.conf" -o /etc/nginx/nginx.conf

# Create necessary directories
mkdir -p /var/cache/nginx
mkdir -p /etc/nginx/conf.d
mkdir -p /etc/nginx/certs
mkdir -p /www
mkdir -p /www/logs
mkdir -p /www/default
chmod -R 755 /www  # 使用 755 而不是 777 更安全
echo -e "${GREEN}[OK] Nginx 目录创建完成${NC}"

# Create nginx user (如果用户不存在才创建)
echo -e "${YELLOW}[12/12] 创建 nginx user...${NC}"
if ! id -u nginx >/dev/null 2>&1; then
    useradd -M -s /sbin/nologin nginx
    echo -e "${GREEN}[OK] nginx 用户创建完成${NC}"
else
    echo -e "${GREEN}[OK] nginx 用户已存在${NC}"
fi

# Reload systemd and enable Nginx
echo -e "${YELLOW}启动 Nginx 服务...${NC}"
systemctl daemon-reload
systemctl enable --now nginx

# Check Nginx status
echo -e "${BLUE}========================================${NC}"
systemctl status nginx --no-pager
echo -e "${BLUE}========================================${NC}"

# 记录结束时间
END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}[SUCCESS] Nginx 安装完成！${NC}"
echo -e "${GREEN}[INFO] 开始时间: $START_TIME${NC}"
echo -e "${GREEN}[INFO] 结束时间: $END_TIME${NC}"
echo -e "${GREEN}========================================${NC}"
