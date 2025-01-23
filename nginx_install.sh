#!/bin/bash

# Set error handling
set -e
set -o pipefail

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Use sudo." 
   exit 1
fi

# Update and upgrade system packages
echo "Updating system packages..."
apt update && apt upgrade -y && apt dist-upgrade -y && apt full-upgrade -y && apt autoremove -y

# Install required dependencies
echo "Installing build dependencies..."
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
echo "Downloading Nginx $NGINX_VERSION..."
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

echo "Configuring Nginx..."
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

echo "Compiling Nginx..."
make

echo "Installing Nginx..."
make install

# Create systemd service file
echo "Creating Nginx systemd service..."
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
echo "Creating Nginx configuration file..."
cat > /etc/nginx/nginx.conf << 'EOF'
user nginx nginx;
worker_processes auto;
worker_cpu_affinity auto;
worker_priority -20;
worker_rlimit_nofile 51200;

events
{
    use epoll;
    worker_connections 10240;
    multi_accept on;
}

http
{
    include mime.types;
    # set_real_ip_from 0.0.0.0/0;
    # real_ip_header CF-Connecting-IP;

    default_type  application/octet-stream;
    charset utf-8;

    http2 on;

    log_format details '[$time_local][$status]|[Client] "$remote_addr" |[Host] "$host" |[Refer] "$http_referer" |[UA] "$http_user_agent" |[REQ] "$request" |[CONNECT] "$connection_requests" |[TIME] "$request_time" |[LENGTH] "$bytes_sent" |[UPSTREAM] "$upstream_addr" |[U_HEAD_TIME] "$upstream_header_time" |[U_CON_TIME] "$upstream_connect_time" |[U_RSP_TIME] "$upstream_response_time" |[U_STATUS] "$upstream_status" |[U_LENGTH] "$upstream_response_length"';

    server_names_hash_bucket_size 512;
    client_header_buffer_size 32k;
    large_client_header_buffers 4 32k;
    client_max_body_size 50m;

    # Perf
    access_log off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    reset_timedout_connection on;
    client_body_timeout 10;
    send_timeout 2;
    keepalive_timeout 60;

    # SSL
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
    ssl_ecdh_curve X25519:secp384r1;
    ssl_session_cache shared:SSL:30m;
    ssl_session_timeout 24h;
    ssl_session_tickets on;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 223.5.5.5 223.6.6.6 valid=60s;
    resolver_timeout 5s;
    ssl_early_data on;
    ssl_buffer_size 8k;

    ##
    # Connection header for WebSocket reverse proxy
    ##
    map $http_upgrade $connection_upgrade {
      default upgrade;
      '' close;
    }

    # fastcgi
    fastcgi_connect_timeout 300;
    fastcgi_send_timeout 300;
    fastcgi_read_timeout 300;
    fastcgi_buffer_size 64k;
    fastcgi_buffers 4 64k;
    fastcgi_busy_buffers_size 128k;
    fastcgi_temp_file_write_size 256k;
    fastcgi_intercept_errors on;

    # compress
    gzip on;
    gzip_min_length 1k;
    gzip_buffers 4 16k;
    gzip_http_version 1.1;
    gzip_comp_level 6;
    gzip_types
        text/css
        text/javascript
        text/xml
        text/plain
        text/x-component
        application/javascript
        application/x-javascript
        application/json
        application/xml
        application/rss+xml
        application/atom+xml
        font/truetype
        font/opentype
        application/vnd.ms-fontobject
        image/svg+xml;
    gzip_vary on;
    gzip_proxied expired no-cache no-store private auth;
    gzip_disable "MSIE [1-6]\.";
    brotli on;
    brotli_comp_level 6;
    brotli_types
        text/css
        text/javascript
        text/xml
        text/plain
        text/x-component
        application/javascript
        application/x-javascript
        application/json
        application/xml
        application/rss+xml
        application/atom+xml
        font/truetype
        font/opentype
        application/vnd.ms-fontobject
        image/svg+xml;

    # Others
    limit_conn_zone $binary_remote_addr zone=perip:10m;
    limit_conn_zone $server_name zone=perserver:10m;
    server_tokens off;
    ## QUIC
    http3 on;
    http3_hq on;
    quic_retry on;
    add_header Alt-Svc 'h3=":443"; ma=86400';

    # Default server
    server
    {
        listen 80 default_server;
        listen 443 ssl default_server;
        listen 443 quic reuseport;
        server_name _;
        ssl_reject_handshake on;
        location /connection-test {
            default_type  application/json;
            return 200 '{"code":0, "message":""}';
        }
        location / {
            return 444;
        }
        access_log  /www/logs/nxdomain.com.log details;
    }

    # Include other conf
    include /etc/nginx/conf.d/*.conf;
}
EOF

# Create necessary directories
echo "Creating Nginx directories..."
mkdir -p /var/cache/nginx
mkdir -p /etc/nginx/conf.d
mkdir -p /etc/nginx/certs
mkdir -p /www
mkdir -p /www/logs
mkdir -p /www/default
chmod -R 777 /www

# Create nginx user
echo "Creating nginx user..."
useradd -M -s /sbin/nologin nginx

# Reload systemd and enable Nginx
echo "Starting Nginx service..."
systemctl daemon-reload
systemctl enable --now nginx

# Check Nginx status
systemctl status nginx

echo "Nginx installation and configuration completed successfully!"
