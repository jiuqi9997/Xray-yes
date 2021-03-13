#!/usr/bin/env bash
# Github: https://github.com/jiuqi9997/Xray-yes
# Script link: https://github.com/jiuqi9997/Xray-yes/raw/main/xray-yes-en.sh
# Supported systems: Debian 9+/Ubuntu 18.04+/CentOS 7+
# Thanks for using.
#

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?
script_version="1.1.69"
nginx_dir="/etc/nginx"
nginx_conf_dir="/etc/nginx/conf.d"
website_dir="/home/wwwroot"
xray_dir="/usr/local/etc/xray"
xray_log_dir="/var/log/xray"
xray_access_log="$xray_log_dir/access.log"
xray_error_log="$xray_log_dir/error.log"
xray_conf="/usr/local/etc/xray/config.json"
cert_dir="/usr/local/etc/xray"
info_file="$HOME/xray.inf"

check_root() {
	if [[ $EUID -ne 0 ]]; then
		error "You have to run this script as root."
	fi
}

color() {
	Green="\033[32m"
	Red="\033[31m"
	Yellow="\033[33m"
	GreenBG="\033[42;37m"
	RedBG="\033[41;37m"
	Font="\033[0m"
}

info() {
	echo "[*] $*"
}

error() {
	echo -e "${Red}[-]${Font} $*"
	exit 1
}

success() {
	echo -e "${Green}[+]${Font} $*"
}

warning() {
	echo -e "${Yellow}[*]${Font} $*"
}

panic() {
	echo -e "${RedBG}$*${Font}"
	exit 1
}

update_script() {
	fail=0
	ol_version=$(curl -sL github.com/jiuqi9997/Xray-yes/raw/main/xray-yes-en.sh | grep "script_version=" | head -1 | awk -F '=|"' '{print $3}')
	if [[ ! $(echo -e "$ol_version\n$script_version" | sort -rV | head -n 1) == "$script_version" ]]; then
		wget -O xray-yes-en.sh github.com/jiuqi9997/Xray-yes/raw/main/xray-yes-en.sh || fail=1
		[[ $fail -eq 1 ]] && warning "Failed to update" && sleep 2 && return 0
		success "Successfully updated"
		sleep 2
		bash xray-yes-en.sh "$*"
		exit 0
	fi
}

install_all() {
	prepare_installation
	sleep 3
	check_env
	install_packages
	install_acme
	install_xray
	generate_uuid
	issue_certificate
	configure_xray
	xray_restart
	configure_nginx
	finish
	exit 0
}

prepare_installation() {
	get_info
	read -rp "Your domain: " xray_domain
	[[ -z $xray_domain ]] && install_all
	echo ""
	echo "Method:"
	echo ""
	echo "1. IPv4 only"
	echo "2. IPv6 only"
	echo "3. IPv4 & IPv6"
	echo ""
	read -rp "Enter a number (default IPv4 only): " ip_type
	[[ -z $ip_type ]] && ip_type=1
	if [[ $ip_type -eq 1 ]]; then
		domain_ip=$(ping -4 "$xray_domain" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
		server_ip=$(curl -sL https://api64.ipify.org -4 || fail=1)
		[[ $fail -eq 1 ]] && error "Failed to get local IP address"
		[[ "$server_ip" == "$domain_ip" ]] && success "The domain name has been resolved to the local IP address" && success=1
		if [[ $success -ne 1 ]]; then
			warning "The domain name is not resolved to the local IP address, the certificate issuance may fail"
			read -rp "Continue? (yes/no): " choice
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
		[[ $fail -eq 1 ]] && error "Failed to get the local IP address"
		[[ "$server_ip" == "$domain_ip" ]] && success "The domain name has been resolved to the local IP address" && success=1
		if [[ $success -ne 1 ]]; then
			warning "The domain name is not resolved to the local IP address, the certificate issuance may fail"
			read -rp "Continue? (yes/no):" choice
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
		[[ $fail -eq 1 ]] && error "Failed to get the local IP address (IPv4)"
		[[ "$server_ip" == "$domain_ip" ]] && success "The domain name has been resolved to the local IP address (IPv4)" && success=1
		if [[ $success -ne 1 ]]; then
			warning "The domain name is not resolved to the local IP address (IPv4), the certificate issuance may fail"
			read -rp "Continue? (yes/no):" choice
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
		[[ $fail -eq 1 ]] && error "Failed to get the local IP address (IPv6)"
		[[ "$server_ip" == "$domain_ip" ]] && success "The domain name has been resolved to the local IP address (IPv6)" && success=1
		if [[ $success -ne 1 ]]; then
			warning "The domain name is not resolved to the local IP address (IPv6), the certificate application may fail"
			read -rp "Continue? (yes/no):" choice
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
		error "Please enter a correct number"
	fi
	read -rp "Please enter the passwd for xray (default UUID): " passwd
	read -rp "Please enter the port for xray (default 443): " port
	[[ -z $port ]] && port=443
	[[ $port -gt 65535 ]] && echo "Please enter a correct port" && install_all
	configure_firewall
	nport=$(rand 10000 20000)
	nport1=$(expr $nport + 1)
	while ss -tnlp | grep -q ":$nport " || ss -tnlp | grep -q ":$nport1 "; do
		nport=$(rand 10000 20000)
		nport1=$(expr $nport + 1)
	done
	success "Everything is ready, the installation is about to start."
}

get_info() {
	source /etc/os-release || source /usr/lib/os-release || panic "The operating system is not supported"
	if [[ $ID == "centos" ]]; then
		PM="yum"
		INS="yum install -y"
	elif [[ $ID == "debian" || $ID == "ubuntu" ]]; then
		PM="apt-get"
		INS="apt-get install -y"
	else
		error "The operating system is not supported"
	fi
}

configure_firewall() {
	fail=0
	if [[ $(type -P ufw) ]]; then
		if [[ $port -ne 443 ]]; then
			ufw allow $port/tcp || fail=1
			ufw allow $port/udp || fail=1
			success "Successfully opened port $port"
		fi
		ufw allow 22,80,443/tcp || fail=1
		ufw allow 1024:65535/udp || fail=1
		yes|ufw enable || fail=1
		yes|ufw reload || fail=1
	elif [[ $(type -P firewalld) ]]; then
		systemctl start --now firewalld
		if [[ $port -ne 443 ]]; then
			firewall-offline-cmd --add-port=$port/tcp || fail=1
			firewall-offline-cmd --add-port=$port/udp || fail=1
			success "Successfully opened port $port"
		fi
		firewall-offline-cmd --add-port=22/tcp --add-port=80/tcp --add-port=443/tcp || fail=1
		firewall-offline-cmd --add-port=1024-65535/udp || fail=1
		firewall-cmd --reload || fail=1
	else
		warning "Please configure the firewall by yourself."
		return 0
	fi
	if [[ $fail -eq 1 ]]; then
		warning "Failed to configure the firewall, please configure by yourself."
	else
		success "Successfully configured the firewall"
	fi
}

rand() {
	min=$1
	max=$(($2-$min+1))
	num=$(cat /dev/urandom | head -n 10 | cksum | awk -F ' ' '{print $1}')
	echo $(($num%$max+$min))
}

check_env() {
	if ss -tnlp | grep -q ":80 "; then
		error "Port 80 is occupied (it's required for certificate application)"
	fi
	if [[ $port -eq "443" ]] && ss -tnlp | grep -q ":443 "; then
		error "Port 443 is occupied"
	elif ss -tnlp | grep -q ":$port "; then
		error "Port $port is occupied"
	fi
}

install_packages() {
	info "Installing the software packages"
	rpm_packages="tar zip unzip openssl lsof git jq socat nginx crontabs"
	apt_packages="tar zip unzip openssl lsof git jq socat nginx cron"
	if [[ $PM == "apt-get" ]]; then
		$PM update
		$INS wget curl gnupg2 ca-certificates dmidecode lsb-release
		update-ca-certificates
		echo "deb http://nginx.org/packages/$ID $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list
		curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
		$PM update
		$INS $apt_packages
	elif [[ $PM == "yum" || $PM == "dnf" ]]; then
		sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
		setenforce 0
		cat > /etc/yum.repos.d/nginx.repo <<EOF
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
		$INS wget curl ca-certificates dmidecode epel-release
		update-ca-trust force-enable
		$INS $rpm_packages
	fi
	mkdir -p $nginx_dir
	cat > $nginx_dir/nginx.conf <<EOF
worker_processes  auto;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    tcp_nopush     on;

    keepalive_timeout  65;

    gzip  on;

    include $nginx_conf_dir/*.conf;
}
EOF
	systemctl enable nginx
	systemctl start nginx
	success "Successfully installed the packages"
}

install_acme() {
	info "Installing acme.sh"
	curl -L get.acme.sh | bash || error "Failed to install acme.sh"
	success "Successfully installed acme.sh"
}

install_xray() {
	info "Installing Xray"
	curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s - install
	ps aux | grep -q xray || error "Failed to install Xray"
	success "Successfully installed Xray"
}

generate_uuid() {
	[[ -z $passwd ]] && uuid=$(xray uuid) || uuidv5=$(xray uuid -i "$passwd") || error "Failed to generate UUID"
}

issue_certificate() {
	info "Issuing a ssl certificate"
	mkdir -p $nginx_conf_dir
	mkdir -p "$website_dir/$xray_domain"
	touch "$website_dir/$xray_domain/index.html"
	cat > "$nginx_conf_dir/default.conf" << EOF
server
{
	listen 80 default_server;
	listen [::]:80 default_server;

	return 444;

	access_log /dev/null;
	error_log /dev/null;
}
EOF
	cat > "$nginx_conf_dir/$xray_domain.conf" <<EOF
server
{
	listen 80;
	listen [::]:80;
	server_name $xray_domain;
	root $website_dir/$xray_domain;

	access_log /dev/null;
	error_log /dev/null;
}
EOF
	nginx -s reload
	/root/.acme.sh/acme.sh --issue -d "$xray_domain" --keylength ec-256 --fullchain-file $cert_dir/cert.pem --key-file $cert_dir/key.pem --webroot "$website_dir/$xray_domain" --renew-hook "systemctl restart xray" --force || error "Failed to issue a ssl certificate"
	success "Successfully issued a ssl certificate"
	generate_certificate
	chmod 600 $cert_dir/*.pem
	if id nobody | grep -q nogroup; then
		chown nobody:nogroup $cert_dir/*.pem
	else
		chown nobody:nobody $cert_dir/*.pem
	fi
}

generate_certificate() {
	info "Generating a self-signed certificate"
	signedcert=$(xray tls cert -domain="$server_ip" -name="$server_ip" -org="$server_ip")
	echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee $cert_dir/self_signed_cert.pem
	echo $signedcert | jq '.key[]' | sed 's/\"//g' > $cert_dir/self_signed_key.pem
	openssl x509 -in $cert_dir/self_signed_key.pem -noout || error "Failed to generate a self-signed certificate"
	success "Successfully generated a self-signed certificate"
}

configure_xray() {
	xray_flow="xtls-rprx-direct"
	cat > $xray_conf << EOF
{
    "log": {
        "access": "$xray_access_log",
        "error": "$xray_error_log",
        "loglevel": "warning"
    },
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private"
                ],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:category-ads-all"
                ],
                "outboundTag": "block"
            }
        ]
    },
    "inbounds": [
        {
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${passwd:-$uuid}",
                        "flow": "$xray_flow"
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": $nport,
                        "xver": 1
                    },
                    {
                        "dest": $nport1,
                        "alpn": "h2",
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "minVersion": "1.2",
                    "certificates": [
                        {
                            "certificateFile": "$cert_dir/self_signed_cert.pem",
                            "keyFile": "$cert_dir/self_signed_key.pem"
                        },
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
            "tag": "direct",
            "protocol": "freedom"
        },
        {
            "tag": "block",
            "protocol": "blackhole"
        }
    ]
}
EOF
}

xray_restart() {
	systemctl restart xray
	ps aux | grep -q xray || error "Failed to restart Xray"
	success "Successfully restarted Xray"
	sleep 2
}

configure_nginx() {
	rm -rf "${website_dir:-~}/$xray_domain"
	mkdir -p "$website_dir/$xray_domain"
	wget -O web.tar.gz https://github.com/jiuqi9997/Xray-yes/raw/main/web.tar.gz
	tar xzvf web.tar.gz -C "$website_dir/$xray_domain"
	rm -rf web.tar.gz
	cat > "$nginx_conf_dir/$xray_domain.conf" <<EOF
server
{
	listen 80;
	listen [::]:80;
	server_name $xray_domain;
	return 301 https://\$http_host\$request_uri;

	access_log  /dev/null;
	error_log  /dev/null;
}

server
{
	listen $nport default_server;
	listen [::]:$nport default_server;
	listen $nport1 http2 default_server;
	listen [::]:$nport1 http2 default_server;

	return 444;

	access_log /dev/null;
	error_log /dev/null;
}

server
{
	listen $nport proxy_protocol;
	listen [::]:$nport proxy_protocol;
	listen $nport1 http2 proxy_protocol;
	listen [::]:$nport1 http2 proxy_protocol;
	server_name $xray_domain;
	index index.html;
	root $website_dir/$xray_domain;
	add_header Strict-Transport-Security "max-age=31536000" always;

	access_log  /dev/null;
	error_log  /dev/null;
}
EOF
	nginx -s reload
}

finish() {
	success "Successfully installed Xray (VLESS+tcp+xtls+nginx)"
	echo ""
	echo ""
	echo -e "$Green Xray configuration $Font" | tee $info_file
	echo -e "$Green Address: $Font $server_ip " | tee -a $info_file
	echo -e "$Green Port: $Font $port " | tee -a $info_file
	echo -e "$Green UUID/Passwd: $Font ${passwd:-$uuid}" | tee -a $info_file
	echo -e "$Green Flow: $Font $xray_flow" | tee -a $info_file
	echo -e "$Green SNI: $Font $xray_domain" | tee -a $info_file
	echo -e "$Green TLS: $Font ${RedBG}XTLS${Font}" | tee -a $info_file
	echo ""
	echo -e "$Green Share link: $Font vless://${uuidv5:-$uuid}@$server_ip:$port?flow=xtls-rprx-direct&security=xtls&sni=$xray_domain#$xray_domain" | tee -a $info_file
	echo ""
	echo -e "${GreenBG} Tip: ${Font}You can use flow control ${RedBG}xtls-rprx-splice${Font} on the Linux platform to get better performance."
}

update_xray() {
	curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s - install
	ps aux | grep -q xray || error "Failed to update Xray"
	success "Successfully updated Xray"
}

uninstall_all() {
	get_info
	curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s - remove --purge
	systemctl stop nginx
	if [[ $ID == "debian" || $ID == "ubuntu" ]]; then
		$PM purge -y nginx
	else
		$PM remove -y nginx
	fi
	rm -rf $nginx_dir
	rm -rf $website_dir
	rm -rf $info_file
	success "Uninstalled Xray and nginx"
	exit 0
}

mod_uuid() {
	uuid_old=$(jq '.inbounds[].settings.clients[].id' $xray_conf || fail=1)
	[[ $(echo "$uuid_old" | jq '' | wc -l) -gt 1 ]] && error "There are multiple UUIDs, please modify by yourself"
	uuid_old=$(echo "$uuid_old" | sed 's/\"//g')
	read -rp "Please enter the password for Xray (default UUID): " passwd
	generate_uuid
	sed -i "s/$uuid_old/${uuid:-$uuidv5}/g" $xray_conf $info_file
	grep -q "$uuid" $xray_conf && success "Successfully modified the UUID" || error "Failed to modify the UUID"
	sleep 2
	xray_restart
	menu
}

mod_port() {
	port_old=$(jq '.inbounds[].port' $xray_conf || fail=1)
	[[ $(echo "$port_old" | jq '' | wc -l) -gt 1 ]] && error "There are multiple ports, please modify by yourself"
	read -rp "Please enter the port for Xray (default 443): " port
	[[ -z $port ]] && port=443
	[[ $port -gt 65535 ]] && echo "Please enter a correct port" && mod_port
	[[ $port -ne 443 ]] && configure_firewall $port
	configure_firewall
	sed -i "s/$port_old/$port/g" $xray_conf $info_file
	grep -q $port $xray_conf && success "Successfully modified the port" || error "Failed to modify the port"
	sleep 2
	xray_restart
	menu
}

show_access_log() {
	[[ -f $xray_access_log ]] && tail -f $xray_access_log || panic "The file doesn't exist"
}

show_error_log() {
	[[ -f $xray_error_log ]] && tail -f $xray_error_log || panic "The file doesn't exist"
}

show_configuration() {
	[[ -f $info_file ]] && cat $info_file && exit 0
	panic "The info file doesn't exist"
}

switch_to_cn() {
	wget -O xray-yes.sh https://github.com/jiuqi9997/Xray-yes/raw/main/xray-yes.sh
	echo "Chinese version: xray-yes.sh"
	sleep 5
	bash xray-yes.sh
	exit 0
}

menu() {
	clear
	echo ""
	echo -e "  XRAY-YES - Install and manage Xray $Red""[$script_version]""$Font"
	echo -e "  https://github.com/jiuqi9997/Xray-yes"
	echo ""
	echo -e " ---------------------------------------"
	echo -e "  ${Green}0.${Font} Update the script"
	echo -e "  ${Green}1.${Font} Install Xray (VLESS+tcp+xtls+nginx)"
	echo -e "  ${Green}2.${Font} Update Xray core"
	echo -e "  ${Green}3.${Font} Uninstall Xray&nginx"
	echo -e " ---------------------------------------"
	echo -e "  ${Green}4.${Font} Modify the UUID"
	echo -e "  ${Green}5.${Font} Modify the port"
	echo -e " ---------------------------------------"
	echo -e "  ${Green}6.${Font} View live access logs"
	echo -e "  ${Green}7.${Font} View live error logs"
	echo -e "  ${Green}8.${Font} View the Xray info file"
	echo -e "  ${Green}9.${Font} Restart Xray"
	echo -e " ---------------------------------------"
	echo -e "  ${Green}10.${Font} 切换到中文"
	echo ""
	echo -e "  ${Green}11.${Font} Exit"
	echo ""
	read -rp "Please enter a number: " choice
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
		switch_to_cn
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
	update_script "$*"
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

main "$*"
