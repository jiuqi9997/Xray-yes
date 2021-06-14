#!/usr/bin/env bash
# Github: https://github.com/jiuqi9997/Xray-yes
# Script link: https://github.com/jiuqi9997/Xray-yes/raw/main/xray-yes.sh
# Supported systems: Debian 9+/Ubuntu 18.04+/CentOS 7+
# Thanks for using.
#

export PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
stty erase ^?
script_version="1.1.84"
xray_dir="/usr/local/etc/xray"
xray_log_dir="/var/log/xray"
xray_access_log="$xray_log_dir/access.log"
xray_error_log="$xray_log_dir/error.log"
xray_conf="/usr/local/etc/xray/config.json"
cert_dir="/usr/local/etc/xray"
info_file="$HOME/xray.inf"

check_root() {
	if [[ $EUID -ne 0 ]]; then
		error "无 root 权限，退出中"
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
	ol_version=$(curl -sL github.com/jiuqi9997/Xray-yes/raw/main/xray-yes.sh | grep "script_version=" | head -1 | awk -F '=|"' '{print $3}')
	if [[ ! $(echo -e "$ol_version\n$script_version" | sort -rV | head -n 1) == "$script_version" ]]; then
		wget -O xray-yes.sh github.com/jiuqi9997/Xray-yes/raw/main/xray-yes.sh || fail=1
		[[ $fail -eq 1 ]] && warning "更新失败" && sleep 2 && return 0
		success "更新成功"
		sleep 2
		bash xray-yes.sh "$*"
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
	crontab_xray
	finish
	exit 0
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
		server_ip=$(curl -sL https://api64.ipify.org -4) || fail=1
		[[ $fail -eq 1 ]] && error "本机 IP 地址获取失败"
		[[ "$server_ip" == "$domain_ip" ]] && success "域名已经解析到本机" && success=1
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
		server_ip=$(curl -sL https://api64.ipify.org -6) || fail=1
		[[ $fail -eq 1 ]] && error "本机 IP 地址获取失败"
		[[ "$server_ip" == "$domain_ip" ]] && success "域名已经解析到本机" && success=1
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
		server_ip=$(curl -sL https://api64.ipify.org -4) || fail=1
		[[ $fail -eq 1 ]] && error "本机 IPv4 地址获取失败"
		[[ "$server_ip" == "$domain_ip" ]] && success "域名已经解析到本机（IPv4）" && success=1
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
		server_ip6=$(curl -sL https://api64.ipify.org -6) || fail=1
		[[ $fail -eq 1 ]] && error "本机 IPv6 地址获取失败"
		[[ "$server_ip" == "$domain_ip" ]] && success "域名已经解析到本机（IPv6）" && success=1
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
	read -rp "请输入 xray 密码（默认使用 UUID）：" passwd
	read -rp "请输入 xray 端口（默认为 443）：" port
	[[ -z $port ]] && port=443
	[[ $port -gt 65535 ]] && echo "请输入正确的端口" && install_all
	configure_firewall
	success "准备完成，即将开始安装"
}

get_info() {
	source /etc/os-release || source /usr/lib/os-release || panic "不支持此操作系统"
	if [[ $ID == "centos" ]]; then
		PM="yum"
		INS="yum install -y"
	elif [[ $ID == "debian" || $ID == "ubuntu" ]]; then
		PM="apt-get"
		INS="apt-get install -y"
	else
		error "不支持此操作系统"
	fi
}

configure_firewall() {
	fail=0
	if [[ $(type -P ufw) ]]; then
		if [[ $port -ne 443 ]]; then
			ufw allow $port/tcp || fail=1
			ufw allow $port/udp || fail=1
			success "开放 $port 端口成功"
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
			success "开放 $port 端口成功"
		fi
		firewall-offline-cmd --add-port=22/tcp --add-port=80/tcp --add-port=443/tcp || fail=1
		firewall-offline-cmd --add-port=1024-65535/udp || fail=1
		firewall-cmd --reload || fail=1
	else
		warning "请自行配置防火墙"
		return 0
	fi
	if [[ $fail -eq 1 ]]; then
		warning "防火墙配置失败，请手动配置"
	else
		success "防火墙配置成功"
	fi
}

check_env() {
	if ss -tnlp | grep -q ":80 "; then
		error "80 端口被占用（需用于申请证书）"
	fi
	if [[ $port -eq "443" ]] && ss -tnlp | grep -q ":443 "; then
		error "443 端口被占用"
	elif ss -tnlp | grep -q ":$port "; then
		error "$port 端口被占用"
	fi
}

install_packages() {
	info "正在安装软件包"
	rpm_packages="tar zip unzip openssl lsof git jq socat crontabs"
	apt_packages="tar zip unzip openssl lsof git jq socat cron"
	if [[ $PM == "apt-get" ]]; then
		$PM update
		$INS wget curl ca-certificates
		update-ca-certificates
		$PM update
		$INS $apt_packages
	elif [[ $PM == "yum" || $PM == "dnf" ]]; then
		sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
		setenforce 0
		$INS wget curl ca-certificates epel-release
		update-ca-trust force-enable
		$INS $rpm_packages
	fi
	success "软件包安装成功"
}

install_acme() {
	info "正在安装 acme.sh"
	curl -L get.acme.sh | bash || error "acme.sh 安装失败，退出中"
	success "acme.sh 安装成功"
}

install_xray() {
	info "正在安装 Xray"
	bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install
	ps -ef | sed '/grep/d' | grep -q bin/xray || error "Xray 安装失败"
	success "Xray 安装成功"
}

generate_uuid() {
	[[ -z $passwd ]] && uuid=$(xray uuid) || uuidv5=$(xray uuid -i "$passwd") || error "生成 UUID 失败"
}

issue_certificate() {
	info "正在申请 SSL 证书"
	/root/.acme.sh/acme.sh --issue \
		-d "$xray_domain" \
		--server letsencrypt \
		--keylength ec-256 \
		--fullchain-file $cert_dir/cert.pem \
		--key-file $cert_dir/key.pem \
		--standalone \
		--force || error "证书申请失败"
	success "证书申请成功"
	chmod 600 $cert_dir/*.pem
	if id nobody | grep -q nogroup; then
		chown nobody:nogroup $cert_dir/*.pem
	else
		chown nobody:nobody $cert_dir/*.pem
	fi
}

configure_xray() {
	xtls_flow="xtls-rprx-direct"
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
            "flow": "$xtls_flow"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "xtls",
        "xtlsSettings": {
          "minVersion": "1.2",
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
	ps -ef | sed '/grep/d' | grep -q bin/xray || error "Xray 重启失败"
	success "Xray 重启成功"
	sleep 2
}

crontab_xray() {
	crontab -l | grep -q Xray || echo -e "$(crontab -l)\n0 0 * * * /usr/bin/bash -c \"\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\"" | crontab || warning "添加 crontab 定时任务失败"
}

finish() {
	success "Xray 安装成功 (VLESS TCP XTLS)"
	echo ""
	echo ""
	echo -e "$Green Xray 配置信息 $Font" | tee $info_file
	echo -e "$Green 地址 (address): $Font $server_ip " | tee -a $info_file
	echo -e "$Green 端口 (port): $Font $port " | tee -a $info_file
	echo -e "$Green 用户id (UUID/密码): $Font ${passwd:-$uuid}" | tee -a $info_file
	echo -e "$Green 流控 (flow): $Font $xtls_flow" | tee -a $info_file
	echo -e "$Green SNI: $Font $xray_domain" | tee -a $info_file
	echo -e "$Green TLS: $Font ${RedBG}XTLS${Font}" | tee -a $info_file
	echo ""
	echo -e "$Green 分享链接:$Font vless://${uuid:-$uuidv5}@$server_ip:$port?flow=$xtls_flow&security=xtls&sni=$xray_domain#$xray_domain" | tee -a $info_file
	echo ""
	echo -e "${GreenBG} 提示：${Font}您可以在 Linux 平台上使用流控 ${RedBG}xtls-rprx-splice${Font} 以获得更好的性能。"
}

update_xray() {
	bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install
	ps -ef | sed '/grep/d' | grep -q bin/xray || error "Xray 更新失败"
	success "Xray 更新成功"
}

install_xray_beta() {
	bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install --beta
	ps -ef | sed '/grep/d' | grep -q bin/xray || error "Xray 更新失败"
	success "Xray 更新成功"
}

uninstall_all() {
	get_info
	bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - remove --purge
	rm -rf $info_file
	success "已卸载 Xray-core"
	exit 0
}

mod_uuid() {
	uuid_old=$(jq '.inbounds[].settings.clients[].id' $xray_conf || fail=1)
	[[ $(echo "$uuid_old" | jq '' | wc -l) -gt 1 ]] && error "有多个 UUID，请自行修改"
	uuid_old=$(echo "$uuid_old" | sed 's/\"//g')
	read -rp "请输入 Xray 密码（默认使用 UUID）：" passwd
	generate_uuid
	sed -i "s/$uuid_old/${uuid:-$uuidv5}/g" $xray_conf $info_file
	grep -q "$uuid" $xray_conf && success "UUID 修改成功" || error "UUID 修改失败"
	sleep 2
	xray_restart
	menu
}

mod_port() {
	port_old=$(jq '.inbounds[].port' $xray_conf || fail=1)
	[[ $(echo "$port_old" | jq '' | wc -l) -gt 1 ]] && error "有多个端口，请自行修改"
	read -rp "请输入 Xray 端口（默认为 443）：" port
	[[ -z $port ]] && port=443
	[[ $port -gt 65535 ]] && echo "请输入正确的端口" && mod_port
	[[ $port -ne 443 ]] && configure_firewall $port
	configure_firewall
	sed -i "s/$port_old/$port/g" $xray_conf $info_file
	grep -q $port $xray_conf && success "端口修改成功" || error "端口修改失败"
	sleep 2
	xray_restart
	menu
}

show_access_log() {
	[[ -e $xray_access_log ]] && tail -f $xray_access_log || panic "文件不存在"
}

show_error_log() {
	[[ -e $xray_error_log ]] && tail -f $xray_error_log || panic "文件不存在"
}

show_configuration() {
	[[ -e $info_file ]] && cat $info_file && exit 0
	panic "配置信息不存在"
}

switch_to_en() {
	wget -O xray-yes-en.sh https://github.com/jiuqi9997/Xray-yes/raw/main/xray-yes-en.sh
	echo "English version: xray-yes-en.sh"
	sleep 5
	bash xray-yes-en.sh
	exit 0
}

menu() {
	clear
	echo ""
	echo -e "  XRAY-YES - 安装管理 Xray $Red""[$script_version]""$Font"
	echo -e "  https://github.com/jiuqi9997/Xray-yes"
	echo ""
	echo -e " ---------------------------------------"
	echo -e "  ${Green}0.${Font} 升级 脚本"
	echo -e "  ${Green}1.${Font} 安装 Xray (VLESS TCP XTLS)"
	echo -e "  ${Green}2.${Font} 升级 Xray-core"
	echo -e "  ${Green}3.${Font} 安装 Xray-core 测试版(Pre)"
	echo -e "  ${Green}4.${Font} 卸载 Xray-core"
	echo -e " ---------------------------------------"
	echo -e "  ${Green}5.${Font} 修改 UUID"
	echo -e "  ${Green}6.${Font} 修改 端口"
	echo -e " ---------------------------------------"
	echo -e "  ${Green}7.${Font} 查看 实时访问日志"
	echo -e "  ${Green}8.${Font} 查看 实时错误日志"
	echo -e "  ${Green}9.${Font} 查看 Xray 配置信息"
	echo -e "  ${Green}10.${Font} 重启 Xray"
	echo -e " ---------------------------------------"
	echo -e "  ${Green}11.${Font} Switch to English"
	echo ""
	echo -e "  ${Green}12.${Font} 退出"
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
		install_xray_beta
		;;
	4)
		uninstall_all
		;;
	5)
		mod_uuid
		;;
	6)
		mod_port
		;;
	7)
		show_access_log
		;;
	8)
		show_error_log
		;;
	9)
		show_configuration
		;;
	10)
		xray_restart
		;;
	11)
		switch_to_en
		;;
	12)
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
