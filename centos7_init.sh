#!/bin/bash
# auth:	tobughan
# date:	2017/07/01
# version:	v0.1
# devenv:	CentOS-7-x86_64-Minimal-1611
#用法帮助
usage() {
	cat <<EOFI
Usage: $0 [OPTION]
OPTION:
	all (expcet net_config)      #执行所有
	history_log                  #历史命令日志
	disable_selinux              #禁用selinux
	useless_user                 #删除无用账号
	ulimit_config                #修改ulimit限制
	disable_ipv6                 #禁用IPV6
	useless_service              #优化服务
	sysctl_config                #优化内核参数
	udev_nic                     #修改网卡名称
	net_config                   #配置网络
	sshd_config                  #配置SSHD
	yum_config                   #配置YUM源
	yum_update                   #安全的自动更新软件包
	vim_config                   #配置VIM编辑器
	mail_config                  #加密的外部企业邮箱
	install_docker               #安装并配置docker
	ntpdate_config               #设置时间同步
EOFI
}
#历史命令日志
history_log() {
	if grep -q '^export LOGIN_IP' /etc/profile;then
		sed -ri "/^export LOGIN_IP/s/(.*LOGIN_IP=)(.*)/\1\$(who am i | awk '{print \$NF}')/" /etc/profile
	else
		echo "export LOGIN_IP=\$(who am i | awk '{print \$NF}')" >>/etc/profile
	fi
	if grep -q '^export PROMPT_COMMAND' /etc/profile;then
		sed -ri "/^export PROMPT_COMMAND/s#(.*LOGIN_IP=)(.*)#\1'{ msg=\$(history 1 | { read x y; echo \$y; });echo \$(date +\"%Y-%m-%d %H:%M:%S\") [\$(whoami)@\$SSH_USER\$LOGIN_IP \$(pwd) ]\" \$msg\" >>/var/log/.history; }'#" \
		/etc/profile
	else
		echo "export PROMPT_COMMAND='{ msg=\$(history 1 | { read x y; echo \$y; });echo \$(date +\"%Y-%m-%d %H:%M:%S\") [\$(whoami)@\$SSH_USER\$LOGIN_IP \$(pwd) ]\" \$msg\" >>/var/log/.history; }'" \
		>>/etc/profile
	fi
}
#禁用selinux
disable_selinux() {
	if grep -q '^SELINUX' /etc/selinux/config;then
		sed -ri '/^SELINUX/s/(SELINUX=)(.*)/\1disabled/' /etc/selinux/config
	else
		echo "SELINUX=disabled" >>/etc/selinux/config
	fi
}
#删除无用账号
useless_user() {
	for u in lp shutdown halt news uucp operator games gopher
	do
		userdel -r $u
	done
	for g in lp news uucp games di
	do
		groupdel $g
	done
}
#修改ulimit限制
ulimit_config() {
	cat > /etc/security/limits.d/30-nofile.conf << EOFI
*          soft    nofile    102400
*          hard    nofile    102400
EOFI
	cat > /etc/security/limits.d/20-nproc.conf << EOFI
*          soft    nproc     102400
*          hard    nproc     102400
EOFI
}
#禁用IPv6
disable_ipv6() {
	grep '^GRUB_CMDLINE_LINUX' /etc/default/grub|grep -q 'ipv6.disable=1'
	if [ $? -ne 0 ];then
		sed -ri '/^GRUB_CMDLINE_LINUX/s/(.*)(rhgb.*)/\1ipv6.disable=1 \2/' /etc/default/grub
		grub2-mkconfig -o /boot/grub2/grub.cfg
	fi
}
#优化服务
useless_service() {
	yum remove -y postfix
	yum remove -y firewalld-*
	yum remove -y NetworkManager-*
	grep '^After' /etc/systemd/system/multi-user.target.wants/sshd.service|grep -q 'network.service'
	if [ $? -ne 0 ];then
		sed -ri '/^After/s/(.*)/\1 network.service/' /etc/systemd/system/multi-user.target.wants/sshd.service
	fi
}
#内核参数优化
sysctl_config() {
	cat > /etc/sysctl.conf << EOFI
#消息队列
kernel.msgmnb = 65536
kernel.msgmax = 65536
#共享内存
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
#网络参数优化
net.core.netdev_max_backlog = 262144
net.core.somaxconn = 65535
net.core.optmem_max = 81920
net.core.wmem_default = 8388608
net.core.rmem_default = 8388608
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_mem = 94500000 915000000 927000000
net.ipv4.tcp_max_orphans = 3276800
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.send_redirects = 0
#redis参数
vm.overcommit_memory = 1
vm.swappiness = 0
#IO参数优化
vm.dirty_background_ratio = 5
vm.dirty_ratio = 20
#LVS忽略VIP的arp请求
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
EOFI
	sysctl -p
}
#修改网卡名称
udev_nic() {
	#修改内核启动参数
	grep '^GRUB_CMDLINE_LINUX' /etc/default/grub |grep -q 'net.ifnames'
	if [ $? -ne 0 ];then
		sed -ri '/^GRUB_CMDLINE_LINUX/s/(.*)(rhgb.*)/\1net.ifnames=0 biosdevname=0 \2/' /etc/default/grub
		grub2-mkconfig -o /boot/grub2/grub.cfg
	fi
	#获取需要修改的以太网卡的MAC地址
	nic_macs=$(ip addr|grep -B 1 'link/ether'|grep -v -- "--"|sed -n '{N;s/\n/\t/p}'|grep -v docker0|awk '{print $13}'|xargs)
	#设置udev映射关系
	nic_num=0
	for mac in $nic_macs
	do
		grep -q "eth$nic_num" /etc/udev/rules.d/70-persistent-ipoib.rules
		if [ $? -ne 0 ];then
			echo "SUBSYSTEM==\"net\", ACTION==\"add\", DRIVERS==\"?*\", ATTR{address}==\"$mac\", ATTR{type}==\"1\", KERNEL==\"eth*\", NAME=\"eth$nic_num\"" \
			>>/etc/udev/rules.d/70-persistent-ipoib.rules
		fi
		let nic_num++
	done
}
#网络设置
get_wanip() {
	wanip=255.255.255.255
	num=1
	while [ $(echo $wanip|awk -F. '{print $1}') -ge 255 -o $(echo $wanip|awk -F. '{print $1}') -le 0 ] \
	|| [ $(echo $wanip|awk -F. '{print $2}') -ge 255 ] \
	|| [ $(echo $wanip|awk -F. '{print $3}') -ge 255 ] \
	|| [ $(echo $wanip|awk -F. '{print $4}') -ge 255 -o $(echo $wanip|awk -F. '{print $4}') -le 0 ]
	do
		if [ $num -gt 1 ];then
			echo "IP地址格式不正确，请重新输入！"
		fi
		read -p "请输入一个公网IP，如何不需要配置公网网络，请直接按回车键进入配置内网网络: " wanip
		if [ -n "$wanip" ];then
			if ! echo $wanip|egrep -q '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$';then
				wanip=255.255.255.255
			fi
			let num++
		else
			break
		fi
	done
}
get_wgateway() {
	wgateway=${wanip%.*}.255
	num=1
	while [ $(echo $wgateway|awk -F. '{print $4}') -ge 255 -o $(echo $wgateway|awk -F. '{print $4}') -le 0 ] \
	|| [ "${wgateway%.*}" != "${wanip%.*}" ] 
	do
		if [ $num -gt 1 ];then
			echo "网关地址格式不正确，请重新输入！"
		fi
		read -p "请输入一个网关地址为你的公网IP(默认值为 ${wanip%.*}.1): " wgateway
		if [ -n "$wgateway" ];then
			if ! echo $wgateway|egrep -q '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$';then
				wgateway=${wanip%.*}.255
			fi
			let num++
		else
			wgateway=${wanip%.*}.1
			break
		fi
	done
}
set_wanip() {
	wanfile=/etc/sysconfig/network-scripts/ifcfg-eth0
	sed -ri '/^BOOTPROTO/s/(BOOTPROTO=)(.*)/\1static/' $wanfile
	sed -ri '/^ONBOOT/s/(ONBOOT=)(.*)/\1yes/' $wanfile
	if grep -q '^IPADDR' $wanfile;then
		sed -ri "/^IPADDR/s/(IPADDR=)(.*)/\1$wanip/" $wanfile
	else
		echo IPADDR=$wanip >>$wanfile
	fi
	if grep -q '^NETMASK' $wanfile;then
		sed -ri "/^NETMASK/s/(NETMASK=)(.*)/\1255.255.255.0/" $wanfile
	else
		echo NETMASK=255.255.255.0 >>$wanfile
	fi
}
set_wgateway() {
	if grep -q '^GATEWAY' $wanfile;then
		sed -ri "/^GATEWAY/s/(GATEWAY=)(.*)/\1$wgateway/" $wanfile
	else
		echo GATEWAY=$wgateway >>$wanfile
	fi
}
get_lanip() {
	lanip=255.255.255.255
	num=1
	while [ $(echo $lanip|awk -F. '{print $1}') -ge 255 -o $(echo $lanip|awk -F. '{print $1}') -le 0 ] \
	|| [ $(echo $lanip|awk -F. '{print $2}') -ge 255 ] \
	|| [ $(echo $lanip|awk -F. '{print $3}') -ge 255 ] \
	|| [ $(echo $lanip|awk -F. '{print $4}') -ge 255 -o $(echo $lanip|awk -F. '{print $4}') -le 0 ]
	do
		if [ $num -gt 1 ];then
			echo "IP地址格式不正确，请重新输入！"
		fi
		read -p "请输入一个内网IP地址: " lanip
		if [ -n "$lanip" ];then
			if ! echo $lanip|egrep -q '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$';then
				lanip=255.255.255.255
			fi
			let num++
		else
			if [ -n "$wanip" ];then
				break
			else
				echo "内网网络不能也不设置"
				lanip=255.255.255.255
			fi
		fi
	done
}
get_lgateway() {
	lgateway=${lanip%.*}.255
	num=1
	while [ $(echo $lgateway|awk -F. '{print $4}') -ge 255 -o $(echo $lgateway|awk -F. '{print $4}') -le 0 ] \
	|| [ "${lgateway%.*}" != "${lanip%.*}" ]
	do
		if [ $num -gt 1 ];then
			echo "网关地址格式不正确，请重新输入！"
		fi
		read -p "请输入一个网关地址为你的内网IP(default ${lanip%.*}.1): " lgateway
		if [ -n "$lgateway" ];then
			if ! echo $lgateway|egrep -q '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$';then
				lgateway=${lanip%.*}.255
			fi
			let num++
		else
			lgateway=${lanip%.*}.1
			break
		fi
	done
}
set_lanip() {
	lanfile=/etc/sysconfig/network-scripts/ifcfg-eth1
	sed -ri '/^BOOTPROTO/s/(BOOTPROTO=)(.*)/\1static/' $lanfile
	sed -ri '/^ONBOOT/s/(ONBOOT=)(.*)/\1yes/' $lanfile
	if grep -q '^IPADDR' $lanfile;then
		sed -ri "/^IPADDR/s/(IPADDR=)(.*)/\1$lanip/" $lanfile
	else
		echo IPADDR=$lanip >>$lanfile
	fi
	if grep -q '^NETMASK' $lanfile;then
		sed -ri "/^NETMASK/s/(NETMASK=)(.*)/\1255.255.255.0/" $lanfile
	else
		echo NETMASK=255.255.255.0 >>$lanfile
	fi
}
set_lgateway() {
	if grep -q '^GATEWAY' $lanfile;then
		sed -ri "/^GATEWAY/s/(GATEWAY=)(.*)/\1$lgateway/" $lanfile
	else
		echo GATEWAY=$lgateway >>$lanfile
	fi
}
net_config() {
	echo "--------设置网络开始--------"
	echo "------开始设置公网网络------"
  	get_wanip
	if [ -z "$wanip" ];then
		echo "------开始设置内网网络------"
		get_lanip
		get_lgateway
		set_lanip
		set_lgateway
	else
		get_wgateway
		set_wanip
		set_wgateway
		echo "------开始设置内网网络------"
		get_lanip
		if [ -n "$lanip" ];then
			set_lanip
		fi
	fi
	echo "--------网络设置完毕--------"
}
#修改sshd配置
sshd_config() {
	sed -i 's/^#AddressFamily any$/AddressFamily inet/' /etc/ssh/sshd_config
	sed -i 's/^GSSAPIAuthentication yes$/GSSAPIAuthentication no/' /etc/ssh/sshd_config
	sed -i 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
	grep -q 'pam_tally2.so' /etc/pam.d/sshd
	if [ $? -ne 0 ];then
		sed -i '/pam_sepermit/a\auth       required     pam_tally2.so onerr=fail deny=3 unlock_time=60 even_deny_root root_unlock_time=180' \
		/etc/pam.d/sshd
	fi
}
#yum源配置
yum_config() {
	yum install -y wget epel-release ntpdate
	wget -O /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
	sed -i '/aliyuncs/d' /etc/yum.repos.d/CentOS-Base.repo
	wget -O /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo
	sed -i '/aliyuncs/d' /etc/yum.repos.d/epel.repo
	yum clean all
	yum makecache
}
#自动安全的更新
yum_update() {
	yum install -y yum-cron
	sed -i 's/update_cmd = default/update_cmd = security/' /etc/yum/yum-cron.conf
	sed -i 's/apply_updates = no/apply_updates = yes/' /etc/yum/yum-cron.conf
	systemctl enable yum-cron.service
	systemctl restart yum-cron.service
}
#配置VIM编辑器
vim_config() {
	yum install -y vim-en*
	grep -q 'set tabstop' /etc/vimrc
	if [ $? -ne 0 ];then
		sed -i '/set ruler/a\set tabstop=2' /etc/vimrc
	fi
}
#加密的外部企业邮箱
mail_config() {
	yum install -y mailx
	if [ ! -f /etc/mail.rc.bak ];then
		egrep -v '#|^$' /etc/mail.rc >/etc/mail.rc.bak
	fi
	mailfrom=server@juntu.com
	mailserver=smtp.exmail.qq.com
	mailuser=server@juntu.com
	mailpass=
	certdir=~/.mailxcerts
	cat >/etc/mail.rc <<EOFI
set from=$mailfrom
set smtp=smtps://$mailserver:465
set smtp-auth-user=$mailuser
set smtp-auth-password=$mailpass
set smtp-auth=login
set ssl-verify=ignore
set nss-config-dir=$certdir
EOFI
	cat /etc/mail.rc.bak >>/etc/mail.rc
	mkdir -p $certdir
	certutil -N -d $certdir
	echo -n |openssl s_client -showcerts -connect $mailserver:465 >$certdir/certs
	sed -ne '/0 s:/,/1 s:/{/-BEGIN/,/-END/p}' $certdir/certs >$certdir/subjectcert
	sed -ne '/1 s:/,${/-BEGIN/,/-END/p}' $certdir/certs >$certdir/issuercert
	subject=$(awk -F= '/subject/ {print $NF}' $certdir/certs)
	issuer=$(awk -F= '/issuer/ {print $NF}' $certdir/certs)
	certutil -A -n "$issuer" -t "CT,," -d $certdir -i $certdir/issuercert
	certutil -A -n "$subject" -t "CT,," -d $certdir -i $certdir/subjectcert
	rm -f $certdir/certs $certdir/subjectcert $certdir/issuercert
}
#安装并配置docker-ce
install_docker() {
	yum install -y yum-utils device-mapper-persistent-data lvm2
	yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
	sed -i 's#download.docker.com#mirrors.aliyun.com/docker-ce#' /etc/yum.repos.d/docker-ce.repo
	yum makecache fast
	yum -y install docker-ce
	systemctl enable docker.service
	systemctl start docker.service
	cat > /etc/docker/daemon.json <<EOFI
{
  "registry-mirrors": ["https://bm5sgu8k.mirror.aliyuncs.com"],
  "insecure-registries": ["http://docker.juntu.com"]
}
EOFI
	systemctl daemon-reload
	systemctl restart docker.service
}
#时间同步
ntpdate_config() {
	grep -q '/usr/sbin/ntpdate' /var/spool/cron/root
	if [ $? -ne 0 ];then
		echo "11 */1 * * * /usr/sbin/ntpdate -s ntp1.aliyun.com" >>/var/spool/cron/root
	fi
}
if [ -z $1 ];then
	usage
fi
if [ "$1" == "all" ];then
	history_log
	disable_selinux
	useless_user
	ulimit_config
	disable_ipv6
	useless_service
	sysctl_config
	sshd_config
	yum_config
	yum_update
	vim_config
	mail_config
	install_docker
	ntpdate_config
else
	$1
fi
