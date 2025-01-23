#!/bin/bash

# Color codes
RED='\033[0;31m'
NC='\033[0m' # No Color


# Set error handling
set -e
set -o pipefail

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "${RED}This script must be run as root. Use sudo.${NC}" 
   exit 1
fi

# Update and upgrade system packages
echo  "${RED}Updating system packages...${NC}"
apt update && apt upgrade -y && apt dist-upgrade -y && apt full-upgrade -y && apt autoremove -y

# Install required dependencies
echo "${RED}Installing build dependencies...${NC}"
apt install -y build-essential git cmake libpcre3 libpcre3-dev libpcre2-dev zlib1g-dev \
               openssl libssl-dev libxml2-dev libxslt1-dev libgd-dev libgeoip-dev \
               libgoogle-perftools-dev libperl-dev perl-base perl

# Create compilation directory
mkdir -p /home/compile/nginx
export COMPILE_PATH="/home/compile/nginx"
cd $COMPILE_PATH

# Set Nginx version
export NGINX_VERSION="1.25.3"

# Download and prepare Nginx source
echo "${RED}Downloading Nginx $NGINX_VERSION...${NC}"
wget https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
tar -zxvf nginx-$NGINX_VERSION.tar.gz
rm nginx-$NGINX_VERSION.tar.gz
mv nginx-$NGINX_VERSION nginx_src

# Clone Brotli module
git clone https://github.com/google/ngx_brotli
cd ngx_brotli
git submodule update --init
cd ..

# Configure and compile Nginx
cd nginx_src

echo "${RED}Configuring Nginx...${NC}"
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

echo "${RED}Compiling Nginx...${NC}"
make

echo "${RED}Installing Nginx...${NC}"
make install

# Create systemd service file
echo "${RED}Creating Nginx systemd service...${NC}"
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

# Backup original nginx.conf and create new configuration
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.b

# Create new nginx.conf
echo "${RED}Creating Nginx configuration file...${NC}"
sudo curl -L "https://raw.githubusercontent.com/CKBTester/install_script/main/nginx.conf" -o /etc/nginx/nginx.conf

# Create necessary directories
echo "${RED}Creating Nginx directories...${NC}"
mkdir -p /var/cache/nginx
mkdir -p /etc/nginx/conf.d
mkdir -p /etc/nginx/certs
mkdir -p /www
mkdir -p /www/logs
mkdir -p /www/default
chmod -R 777 /www

# Create nginx user
echo "${RED}Creating nginx user...${NC}"
useradd -M -s /sbin/nologin nginx

# Reload systemd and enable Nginx
echo "${RED}Starting Nginx service...${NC}"
systemctl daemon-reload
systemctl enable --now nginx

# Check Nginx status
systemctl status nginx

echo "Nginx installation and configuration completed successfully!${NC}"
