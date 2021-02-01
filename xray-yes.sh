#!/bin/bash
# Github: https://github.com/jiuqi9997/xray-yes
# Script link: https://github.com/jiuqi9997/xray-yes/raw/main/xray-yes.sh
#
# Thanks for using.
#

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
stty erase ^?
script_version="1.0.82"
nginx_dir="/etc/nginx"
nginx_conf_dir="/etc/nginx/conf"
website_dir="/home/wwwroot"
nginx_version="1.18.0"
openssl_version="1.1.1g"
jemalloc_version="5.2.1"
xray_dir="/usr/local/etc/xray"
xray_log_dir="/var/log/xray"
xray_access_log="$xray_log_dir/access.log"
xray_error_log="$xray_log_dir/error.log"
xray_conf="/usr/local/etc/xray/config.json"
cert_dir="/usr/local/etc/xray"
info_file="$HOME/xray.inf"

get_info() {
	if [[ $(type -P yum) ]]; then
		PM="yum"
		INS="yum install -y"
	elif [[ $(type -P dnf) ]]; then
		PM="dnf"
		INS="dnf install -y"
	elif [[ $(type -P apt-get) ]]; then
		PM="apt-get"
		INS="apt-get install -y"
	elif [[ $(type -P pacman) ]]; then
		PM="pacman"
		INS="pacman -Syu --noconfirm"
	elif [[ $(type -P zypper) ]]; then
		PM="zypper"
		INS="zypper install -y"
	else
		error "不支持此操作系统，正在退出"
	fi
	source "/etc/os-release" || source "/usr/lib/os-release" || panic "不支持此操作系统，正在退出"
	sys="$ID"
	ver="$VERSION_ID"
}

check_env() {
	if [[ $(ss -tnlp | grep ":80 ") ]]; then
		error "80 端口被占用（需用于申请证书）"
	fi
	if [[ $port -eq "443" && $(ss -tnlp | grep ":443 ") ]]; then
		error "443 端口被占用"
	elif [[ $(ss -tnlp | grep ":$port ") ]]; then
		error "$port 端口被占用"
	fi
}

install_packages() {
	info "开始安装软件包"
	$PM update -y
	$PM upgrade -y
	$PM install -y wget curl
	rpm_packages="libcurl-devel tar gcc make zip unzip openssl openssl-devel libxml2 libxml2-devel libxslt* zlib zlib-devel libjpeg-devel libpng-devel libwebp libwebp-devel freetype freetype-devel lsof pcre pcre-devel crontabs icu libicu-devel c-ares libffi-devel bzip2 bzip2-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel xz-devel libtermcap-devel libevent-devel libuuid-devel git jq"
	apt_packages="libcurl4-openssl-dev gcc make zip unzip openssl libssl-dev libxml2 libxml2-dev zlib1g zlib1g-dev libjpeg-dev libpng-dev lsof libpcre3 libpcre3-dev cron net-tools swig build-essential libffi-dev libbz2-dev libncurses-dev libsqlite3-dev libreadline-dev tk-dev libgdbm-dev libdb-dev libdb++-dev libpcap-dev xz-utils git libgd3 libgd-dev libevent-dev libncurses5-dev uuid-dev jq bzip2"
	if [[ $PM == "apt-get" ]]; then
		$INS $apt_packages
	elif [[ $PM == "yum" || $PM == "dnf" ]]; then
		sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
		$INS epel-release
		$INS $rpm_packages
	fi
	success "软件包安装完成"
}

check_root() {
	if [[ $EUID -ne 0 ]]; then
		error "无 root 权限，退出中"
	fi
}

configure_firewall() {
	fail=0
	if [[ $(type -P ufw) ]]; then
		if [[ -n $@ ]]; then
			ufw allow "$@"/tcp || fail=1
			success "开放 $@ 端口成功"
		else
			ufw allow 22,80,443/tcp || fail=1
		fi
		yes|ufw enable || fail=1
		yes|ufw reload || fail=1
	elif [[ $(type -P firewalld) ]]; then
		systemctl start --now firewalld
		if [[ -n $@ ]]; then
			firewall-offline-cmd --add-port="$@"/tcp || fail=1
			success "开放 $@ 端口成功"
		else
			firewall-offline-cmd --add-port=22/tcp --add-port=80/tcp --add-port=443/tcp || fail=1
		fi
		firewall-cmd --reload || fail=1
	else
		warning "请自行配置防火墙"
	fi
	if [[ $fail -eq 1 ]]; then
		warning "防火墙配置失败，请手动配置"
	elif [[ -z $@ ]]; then
		success "防火墙配置成功"
	fi
}

nginx_systemd() {
	cat > "/etc/systemd/system/nginx.service" <<EOF
[Unit]
Description=NGINX web server
After=syslog.target network.target remote-fs.target nss-lookup.target
[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
}

configure_nginx() {
	rm -rf /home/wwwroot/$xray_domain
	mkdir -p /home/wwwroot/$xray_domain
	wget -O web.tar.gz https://github.com/jiuqi9997/xray-yes/raw/main/web.tar.gz
	tar xzvf web.tar.gz -C /home/wwwroot/$xray_domain
	rm -rf web.tar.gz
	mkdir -p "$nginx_conf_dir/vhost"
	cat > "$nginx_conf_dir/vhost/$xray_domain.conf" <<EOF
server
{
	listen 80 proxy_protocol;
	server_name $xray_domain;
	index index.html index.htm index.php default.php default.htm default.html;
	root /home/wwwroot/$xray_domain;

	location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
	{
		expires	  30d;
		error_log off;
		access_log /dev/null;
	}

	location ~ .*\.(js|css)?$
	{
		expires	  12h;
		error_log off;
		access_log /dev/null;
	}
	access_log  /dev/null;
	error_log  /dev/null;
}
EOF
	cat > "$nginx_conf_dir/nginx.conf" << EOF
worker_processes auto;
worker_rlimit_nofile 51200;

events
	{
		use epoll;
		worker_connections 51200;
		multi_accept on;
	}

http
	{
		include	   mime.types;
		default_type  application/octet-stream;
		log_format main
			'\$http_cf_connecting_ip \$http_cf_connecting_ipv6 \$http_cf_ipcountry '
			'\$status \$remote_addr [\$time_local] '
			'"\$request" "\$http_referer" '
			'"\$http_user_agent" \$body_bytes_sent B';
		charset utf-8;
		server_names_hash_bucket_size 512;
		client_header_buffer_size 32k;
		large_client_header_buffers 4 32k;
		client_max_body_size 50m;

		sendfile   on;
		tcp_nopush on;

		keepalive_timeout 60;

		tcp_nodelay on;

		fastcgi_connect_timeout 300;
		fastcgi_send_timeout 300;
		fastcgi_read_timeout 300;
		fastcgi_buffer_size 64k;
		fastcgi_buffers 4 64k;
		fastcgi_busy_buffers_size 128k;
		fastcgi_temp_file_write_size 256k;
		fastcgi_intercept_errors on;

		gzip on;
		gzip_min_length  1k;
		gzip_buffers	 4 16k;
		gzip_http_version 1.1;
		gzip_comp_level 2;
		gzip_types	 text/plain application/javascript application/x-javascript text/javascript text/css application/xml;
		gzip_vary on;
		gzip_proxied   expired no-cache no-store private auth;
		gzip_disable   "MSIE [1-6]\.";

		limit_conn_zone \$binary_remote_addr zone=perip:10m;
		limit_conn_zone \$server_name zone=perserver:10m;

		server_tokens off;
		access_log off;
include /etc/nginx/conf/vhost/*.conf;
}
EOF
}

install_acme() {
	info "开始安装 acme.sh"
	fail=0
	curl https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh | bash -s -- --install-online || fail=1
	[[ $fail -eq 1 ]] &&
	error "acme.sh 安装失败，退出中"
	success "acme.sh 安装成功"
}

install_jemalloc(){
	wget -O jemalloc-$jemalloc_version.tar.bz2 https://github.com/jemalloc/jemalloc/releases/download/$jemalloc_version/jemalloc-$jemalloc_version.tar.bz2
	tar -xvf jemalloc-$jemalloc_version.tar.bz2
	cd jemalloc-$jemalloc_version
	info "编译安装 jamalloc $jemalloc_version"
	./configure
	make -j$(nproc --all) && make install
	echo '/usr/local/lib' >/etc/ld.so.conf.d/local.conf
	ldconfig
	cd ..
	rm -rf jemalloc*
	[[ ! -f '/usr/local/lib/libjemalloc.so' ]] &&
	error "编译安装 jamalloc $jemalloc_version 失败"
	success "编译安装 jamalloc $jemalloc_version 成功"
}

install_nginx() {
	[[ ! -f '/usr/local/lib/libjemalloc.so' ]] && install_jemalloc
	info "编译安装 nginx $nginx_version"
	wget -O openssl-${openssl_version}.tar.gz https://www.openssl.org/source/openssl-$openssl_version.tar.gz
	wget -O nginx-${nginx_version}.tar.gz http://nginx.org/download/nginx-${nginx_version}.tar.gz
	[[ -d nginx-"$nginx_version" ]] && rm -rf nginx-"$nginx_version"
	tar -xzvf nginx-"$nginx_version".tar.gz
	[[ -d openssl-"$openssl_version" ]] && rm -rf openssl-"$openssl_version"
	tar -xzvf openssl-"$openssl_version".tar.gz
	cd nginx-"$nginx_version"
	echo '/usr/local/lib' >/etc/ld.so.conf.d/local.conf
	ldconfig
	./configure --prefix="${nginx_dir}" \
		--with-http_ssl_module \
		--with-http_gzip_static_module \
		--with-http_stub_status_module \
		--with-pcre \
		--with-http_realip_module \
		--with-http_flv_module \
		--with-http_mp4_module \
		--with-http_secure_link_module \
		--with-http_v2_module \
		--with-cc-opt='-O3' \
		--with-ld-opt="-ljemalloc" \
		--with-openssl=../openssl-"$openssl_version"
	make -j$(nproc --all) && make install
	ln -s /etc/nginx/sbin/nginx /usr/bin/nginx
	configure_nginx
	nginx_systemd
	systemctl stop nginx
	systemctl start --now nginx
	[[ ! $(type -P nginx) ]] &&
	error "编译安装 nginx $nginx_version 失败"
	success "编译安装 nginx $nginx_version 成功"
}

issue_certificate() {
	info "申请 SSL 证书"
	fail=0
	/root/.acme.sh/acme.sh --issue -d $xray_domain --keylength ec-256 --fullchain-file "$cert_dir/cert.pem" --key-file "$cert_dir/key.pem" --webroot "$website_dir/$xray_domain" --force || fail=1
	[[ $fail -eq 1 ]] && error "证书申请失败"
	chmod 600 "$cert_dir/cert.pem" "$cert_dir/key.pem"
	if [[ $(grep "nogroup" /etc/group) ]]; then
		chown nobody:nogroup "$cert_dir/cert.pem" "$cert_dir/key.pem"
	else
		chown nobody:nobody "$cert_dir/cert.pem" "$cert_dir/key.pem"
	fi
	success "证书申请成功"
}

configure_xray() {
	[[ -z $uuid ]] && uuid=$(xray uuid)
	xray_flow="xtls-rprx-direct"
	cat > $xray_conf << EOF
{
    "log": {
        "access": "$xray_access_log",
        "error": "$xray_error_log",
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "flow": "$xray_flow"
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 80,
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "$cert_dir/cert.pem",
                            "keyFile": "$cert_dir/key.pem"
                        }
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http","tls"]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ]
}
EOF
}

install_xray() {
	info "安装 xary"
	curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
	configure_xray
	systemctl stop xray
	systemctl start --now xray
	[[ ! $(ps aux | grep xray) ]] && error "xray 安装失败"
	success "xray 安装成功"
}

finish() {
	success "VLESS+tcp+xtls+nginx 安装成功"
	[[ $ip_type -eq 3 ]] && server_ip="$server_ip / $server_ip6"
	echo ""
	echo ""
	echo -e "$Red xray 配置信息 $Font" | tee $info_file
	echo -e "$Red 地址（address）:$Font $server_ip " | tee -a $info_file
	echo -e "$Red 端口（port）：$Font $port " | tee -a $info_file
	echo -e "$Red 用户id（UUID/密码）：$Font $uuid" | tee -a $info_file
	echo -e "$Red 流控（flow）：$Font $xray_flow" | tee -a $info_file
	echo -e "$Red 伪装域名（host）：$Font $xray_domain" | tee -a $info_file
	echo -e "$Red 底层传输安全（tls）：$Font ${RedBG}XTLS${Font}" | tee -a $info_file
	echo ""
	echo -e "${GreenBG} 提示：${Font}您可以在 linux 平台上使用流控 ${RedBG}xtls-rprx-splice${Font} 以获得更好的性能"
}

info() {
	echo "[*] $@"
}

error() {
	echo -e "${Red}[-]${Font} $@"
	exit 1
}

success() {
	echo -e "${Green}[+]${Font} $@"
}

warning() {
	echo -e "${Yellow}[*]${Font} $@"
}

panic() {
	echo -e "${RedBG}$@${Font}"
	exit 1
}

color() {
	Green="\033[32m"
	Red="\033[31m"
	Yellow="\033[33m"
	GreenBG="\033[42;37m"
	RedBG="\033[41;37m"
	Font="\033[0m"
}

prepare_installation() {
	get_info
	read -rp "请输入你的域名：" xray_domain
	[[ -z $xray_domain ]] && install_all
	echo ""
	echo "模式"
	echo ""
	echo "1. IPv4 only"
	echo "2. IPv6 only"
	echo "3. IPv4 & IPv6"
	echo ""
	read -rp "请输入数字（默认为 IPv4 only）：" ip_type
	[[ -z $ip_type ]] && ip_type=1
	if [[ $ip_type -eq 1 ]]; then
		domain_ip=$(ping -4 "$xray_domain" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
		server_ip=$(curl -sL https://api64.ipify.org -4 || fail=1)
		[[ $fail -eq 1 ]] && error "本机 IP 地址获取失败"
		[[ $server_ip == $domain_ip ]] && success "域名已经解析到本机" && success=1
		if [[ $success -ne 1 ]]; then
			warning "域名没有解析到本机，证书申请可能失败"
			read -rp "继续？（yes/no）" choice
			case $choice in
			yes)
				;;
			y)
				;;
			no)
				exit 1
				;;
			n)
				exit 1
				;;
			*)
				exit 1
				;;
			esac
		fi
	elif [[ $ip_type -eq 2 ]]; then
		domain_ip=$(ping -6 "$xray_domain" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
		server_ip=$(curl -sL https://api64.ipify.org -6 || fail=1)
		[[ $fail -eq 1 ]] && error "本机 IP 地址获取失败"
		[[ $server_ip == $domain_ip ]] && success "域名已经解析到本机" && success=1
		if [[ $success -ne 1 ]]; then
			warning "域名没有解析到本机，证书申请可能失败"
			read -rp "继续？（yes/no）" choice
			case $choice in
			yes)
				;;
			y)
				;;
			no)
				exit 1
				;;
			n)
				exit 1
				;;
			*)
				exit 1
				;;
			esac
		fi
	elif [[ $ip_type -eq 3 ]]; then
		domain_ip=$(ping -4 "$xray_domain" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
		server_ip=$(curl -sL https://api64.ipify.org -4 || fail=1)
		[[ $fail -eq 1 ]] && error "本机 IPv4 地址获取失败"
		[[ $server_ip == $domain_ip ]] && success "域名已经解析到本机（IPv4）" && success=1
		if [[ $success -ne 1 ]]; then
			warning "域名没有解析到本机（IPv4），证书申请可能失败"
			read -rp "继续？（yes/no）" choice
			case $choice in
			yes)
				;;
			y)
				;;
			no)
				exit 1
				;;
			n)
				exit 1
				;;
			*)
				exit 1
				;;
			esac
		fi
		domain_ip6=$(ping -6 "$xray_domain" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
		server_ip6=$(curl https://api64.ipify.org -6 || fail=1)
		[[ $fail -eq 1 ]] && error "本机 IPv6 地址获取失败"
		[[ $server_ip == $domain_ip ]] && success "域名已经解析到本机（IPv6）" && success=1
		if [[ $success -ne 1 ]]; then
			warning "域名没有解析到本机（IPv6），证书申请可能失败"
			read -rp "继续？（yes/no）" choice
			case $choice in
			yes)
				;;
			y)
				;;
			no)
				exit 1
				;;
			n)
				exit 1
				;;
			*)
				exit 1
				;;
			esac
		fi
	else
		error "请输入正确的数字"
	fi
	read -rp "请输入 xray 密码（默认使用 UUID）：" uuid
	read -rp "请输入 xray 端口（默认为 443）：" port
	[[ -z $port ]] && port=443
	[[ $port > 65535 ]] && echo "请输入正确的端口" && install_all
	configure_firewall $port
	configure_firewall
	success "准备完成，即将开始安装"
}

install_all() {
	prepare_installation
	sleep 3
	check_env
	install_packages
	install_acme
	install_nginx
	install_xray
	issue_certificate
	xray_restart
	finish
	exit 0
}

update_script() {
	fail=0
	ver=$(curl -sL github.com/jiuqi9997/xray-yes/raw/main/xray-yes.sh | grep "script_version=" | head -1 | awk -F '=|"' '{print $3}')
	if [[ $script_version != $ver ]]; then
		wget -O xray-yes.sh github.com/jiuqi9997/xray-yes/raw/main/xray-yes.sh || fail=1
		[[ $fail -eq 1 ]] && error "更新失败"
		success "更新成功"
		sleep 2
		bash xray-yes.sh $@
		exit 0
	fi
	success "当前是最新版本"
}

update_xray() {
	curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
	[[ ! $(ps aux | grep xray) ]] && error "xray 更新失败"
	success "xray 更新成功"
}

mod_uuid() {
	fail=0
	uuid_old=$(jq '.inbounds[].settings.clients[].id' $xray_conf || fail=1)
	[[ $(echo $uuid_old | jq '' | wc -l) > 1 ]] && error "有多个 UUID，请自行修改"
	uuid_old=$(echo $uuid_old | sed 's/\"//g')
	read -rp "请输入 xray 密码（默认使用 UUID）：" uuid
	[[ -z $uuid ]] && uuid=$(xray uuid)
	sed -i "s/$uuid_old/$uuid/g" $xray_conf $info_file
	[[ $(grep "$uuid" $xray_conf ) ]] && success "UUID 修改成功"
	sleep 2
	xray_restart
	menu
}

mod_port() {
	fail=0
	port_old=$(jq '.inbounds[].port' $xray_conf || fail=1)
	[[ $(echo $port_old | jq '' | wc -l) > 1 ]] && error "有多个端口，请自行修改"
	read -rp "请输入 xray 端口（默认为 443）：" port
	[[ -z $port ]] && port=443
	[[ $port > 65535 ]] && echo "请输入正确的端口" && mod_port
	sed -i "s/$port_old/$port/g" $xray_conf $info_file
	[[ $(grep "$port" $xray_conf ) ]] && success "端口修改成功"
	sleep 2
	xray_restart
	menu
}

xray_restart() {
	systemctl restart xray
	[[ ! $(ps aux | grep xray) ]] && error "xray 重启失败"
	success "xray 重启成功"
	sleep 2
}

show_access_log() {
	[[ -f $xray_access_log ]] && tail -f $xray_access_log || panic "文件不存在"
}

show_error_log() {
	[[ -f $xray_error_log ]] && tail -f $xray_error_log || panic "文件不存在"
}

show_configuration() {
	[[ -f $info_file ]] && cat $info_file && exit 0
	panic "配置信息不存在"
}

uninstall_all() {
	curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- remove --purge
	systemctl stop nginx
	rm -rf $nginx_systemd_file
	rm -rf $nginx_dir
	rm -rf $website_dir
	rm -rf $info_file
	success "卸载完成"
	exit 0
}

switch_to_en() {
	wget -O xray-yes-en.sh https://github.com/jiuqi9997/xray-yes/raw/main/xray-yes-en.sh
	echo "English version: xray-yes-en.sh"
	sleep 5
	bash xray-yes-en.sh
	exit 0
}

menu() {
	clear
	echo ""
	echo -e "  XRAY-YES 安装管理 $Red[$script_version]$Font"
	echo -e "  https://github.com/jiuqi9997/xray-yes"
	echo ""
	echo -e " ---------------------------------------"
	echo -e "  ${Green}0.${Font} 升级 脚本"
	echo -e "  ${Green}1.${Font} 安装 xray (vless+tcp+xtls+nginx)"
	echo -e "  ${Green}2.${Font} 升级 xray core"
	echo -e "  ${Green}3.${Font} 卸载 xray+nginx"
	echo -e " ---------------------------------------"
	echo -e "  ${Green}4.${Font} 修改 UUID"
	echo -e "  ${Green}5.${Font} 修改 端口"
	echo -e " ---------------------------------------"
	echo -e "  ${Green}6.${Font} 查看 实时访问日志"
	echo -e "  ${Green}7.${Font} 查看 实时错误日志"
	echo -e "  ${Green}8.${Font} 查看 xray 配置信息"
	echo -e "  ${Green}9.${Font} 重启 xray"
	echo -e "  ${Green}10.${Font} Switch to English"
	echo ""
	echo -e "  ${Green}11.${Font} 退出"
	echo ""
	read -rp "请输入数字：" choice
	case $choice in
	0)
		update_script
		;;
	1)
		install_all
		;;
	2)
		update_xray
		;;
	3)
		uninstall_all
		;;
	4)
		mod_uuid
		;;
	5)
		mod_port
		;;
	6)
		show_access_log
		;;
	7)
		show_error_log
		;;
	8)
		show_configuration
		;;
	9)
		xray_restart
		;;
	10)
		switch_to_en
		;;
	11)
		exit 0
		;;
	*)
		menu
		;;
	esac
}

main() {
	clear
	check_root
	color
	update_script $@
	case $1 in
	install)
		install_all
		;;
	update)
		update_xray
		;;
	remove)
		uninstall_all
		;;
	purge)
		uninstall_all
		;;
	uninstall)
		uninstall_all
		;;
	*)
		menu
		;;
	esac
}

main $@
