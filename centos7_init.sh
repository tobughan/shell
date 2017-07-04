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
	all                          #执行所有
	history_log                  #历史命令日志
	disable_selinux              #禁用selinux
	del_useless_user             #删除无用账号
	ulimit_config                #修改ulimit限制
	disable_ipv6                 #禁用IPV6
	del_useless_service          #优化服务
	sysctl_config                #优化内核参数
	init_nic_name                #修改网卡名称
	net_config                   #配置网络
	sshd_config                  #配置SSHD
	yum_config                   #配置YUM源
	yum_update                   #安全的自动更新软件包
	vim_config                   #配置VIM编辑器
	install_docker               #安装并配置docker
	ntpdate_config               #设置时间同步
EOFI
}
#历史命令日志
history_log() {
	grep -q 'LOGIN_IP' /etc/profile
	if [ $? -ne 0 ];then
		echo "export LOGIN_IP=\$(who am i | awk '{print \$NF}')" >>/etc/profile
		echo "export PROMPT_COMMAND='{ msg=\$(history 1 | { read x y; echo \$y; });echo \$(date +\"%Y-%m-%d %H:%M:%S\") [\$(whoami)@\$SSH_USER\$LOGIN_IP \$(pwd) ]\" \$msg\" >> /var/log/.history; }'" >>/etc/profile
	fi
}
#禁用selinux
disable_selinux() {
	sed -ri '/^SELINUX=/s/(SELINUX=)(.*)/\1disabled/' /etc/selinux/config
}
#删除无用账号
del_useless_user() {
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
	grep 'GRUB_CMDLINE_LINUX' /etc/default/grub|grep -q 'ipv6.disable=1'
	if [ $? -ne 0 ];then
		sed -ri '/GRUB_CMDLINE_LINUX/s/(.*)(rhgb.*)/\1ipv6.disable=1 \2/' /etc/default/grub
		grub2-mkconfig -o /boot/grub2/grub.cfg
	fi
}
#优化服务
del_useless_service() {
	yum remove -y postfix
	yum remove -y firewalld-*
	yum remove -y NetworkManager-*
	grep 'After' /etc/systemd/system/multi-user.target.wants/sshd.service|grep -q 'network.service'
	if [ $? -ne 0 ];then
		sed -ri '/After/s/(.*)/\1 network.service/' /etc/systemd/system/multi-user.target.wants/sshd.service
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
init_nic_name() {
	#修改内核启动参数
	grep 'GRUB_CMDLINE_LINUX' /etc/default/grub |grep -q 'net.ifnames'
	if [ $? -ne 0 ];then
		sed -ri '/GRUB_CMDLINE_LINUX/s/(.*)(rhgb.*)/\1net.ifnames=0 biosdevname=0 \2/' /etc/default/grub
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
#设置网络
net_config() {
	wanfile=/etc/sysconfig/network-scripts/ifcfg-eth0
	lanfile=/etc/sysconfig/network-scripts/ifcfg-eth1
	read -p "set an wanip: " wanip
	if [ ! -z $wanip ];then
		read -p "set a netmask for wanip(default 255.255.255.0): " wanip_mask
		if [ -z $wanip_mask ];then
			wanip_mask=255.255.255.0
		fi
		read -p "set a gateway for wanip: " gateway
		read -p "set an lanip: " lanip
		read -p "set a netmask for lanip: " lanip_mask
		if [ -z $wanip_mask ];then
			lanip_mask=255.255.255.0
		fi
		sed -i 's/BOOTPROTO=hdcp/BOOTPROTO=static/' $wanfile
		sed -i 's/ONBOOT=no/ONBOOT/' $wanfile
		grep -q 'IPADDR' $wanfile
		if [ $? -ne 0 ];then
			echo "IPADDR=$wanip" >> $wanfile
		else
			sed -ri "/IPADDR/s/(IPADDR=)(.*)/\1$wanip/" $wanfile
		fi
		grep -q 'NETMASK' $wanfile
		if [ $? -ne 0 ];then
			echo "NETMASK=$wanip_mask" >>$wanfile
		else
			sed -ri "/NETMASK/s/(NETMASK=)(.*)/\1$wanip_mask/" $wanfile
		fi
		grep -q 'GATEWAY' $wanfile
		if [ $? -ne 0 ];then
			echo "GATEWAY=$gateway" >>$wanfile
		else
			sed -ri "/GATEWAY/s/(GATEWAY=)(.*)/\1$gateway/" $wanfile
		fi
		sed -i 's/BOOTPROTO=hdcp/BOOTPROTO=static/' $lanfile
		sed -i 's/ONBOOT=no/ONBOOT/' $lanfile
		grep -q 'IPADDR' $lanfile
		if [ $? -ne 0 ];then
			echo "IPADDR=$lanip" >> $lanfile
		else
			sed -ri "/IPADDR/s/(IPADDR=)(.*)/\1$lanip/" $lanfile
		fi
		grep -q 'NETMASK' $lanfile
		if [ $? -ne 0 ];then
			echo "NETMASK=$lanip_mask" >>$lanfile
		else
			sed -ri "/NETMASK/s/(NETMASK=)(.*)/\1$lanip_mask/" $lanfile
		fi
	else
		read -p "set an lanip: " lanip
		read -p "set a netmask for lanip: " lanip_mask
		if [ -z $lanip_mask ];then
			lanip_mask=255.255.255.0
		fi
		read -p "set a gateway for lanip: " gateway
		sed -i 's/BOOTPROTO=hdcp/BOOTPROTO=static/' $lanfile
		sed -i 's/ONBOOT=no/ONBOOT/' $lanfile
		grep -q 'IPADDR' $lanfile
		if [ $? -ne 0 ];then
			echo "IPADDR=$lanip" >> $lanfile
		else
			sed -ri "/IPADDR/s/(IPADDR=)(.*)/\1$lanip/" $lanfile
		fi
		grep -q 'NETMASK' $lanfile
		if [ $? -ne 0 ];then
			echo "NETMASK=$lanip_mask" >>$lanfile
		else
			sed -ri "/NETMASK/s/(NETMASK=)(.*)/\1$lanip_mask/" $lanfile
		fi
		grep -q 'GATEWAY' $lanfile
		if [ $? -ne 0 ];then
			echo "GATEWAY=$gateway" >>$lanfile
		else
			sed -ri "/GATEWAY/s/(GATEWAY=)(.*)/\1$gateway/" $lanfile
		fi
	fi
	read -p "set a dns for this ip: " dns
	echo "nameserver $dns" >/etc/resolv.conf
	systemctl restart network.service
}
#修改sshd配置
sshd_config() {
	sed -i 's/^#Port 22$/Port 33000/' /etc/ssh/sshd_config
	sed -i 's/^#AddressFamily any$/AddressFamily inet/' /etc/ssh/sshd_config
	read -p "input a lan ip: " lanip
	if [ ! -z $lanip ];then
		sed -i "s/#ListenAddress 0.0.0.0/ListenAddress $lanip/" /etc/ssh/sshd_config
	fi
	sed -i 's/^GSSAPIAuthentication yes$/GSSAPIAuthentication no/' /etc/ssh/sshd_config
  sed -i 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
	grep -q 'pam_tally2.so' /etc/pam.d/sshd
	if [ $? -ne 0 ];then
	sed -i '/pam_sepermit/a\auth       required     pam_tally2.so onerr=fail deny=3 unlock_time=60 even_deny_root root_unlock_time=180' /etc/pam.d/sshd
	fi
}
#yum源配置
yum_config() {
	yum install -y wget epel-release
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
	systemctl start yum-cron.service
}
#配置VIM编辑器
vim_config() {
	yum install -y vim-en*
	grep -q 'set tabstop' /et/vimrc
	if [ $? -ne 0 ];then
		sed '/set ruler/a\set tabstop=2' /etc/vimrc
	fi
}
#安装并配置docker-ce
install_docker() {
	yum install -y yum-utils device-mapper-persistent-data lvm2
	yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
	sed -i 's#download.docker.com#mirrors.aliyun.com/docker-ce#' /etc/yum.repos.d/docker-ce.repo
	yum makecache fast
	yum -y install docker-ce
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
	disable_selinux
	del_useless_user
	ulimit_config
	disable_ipv6
	del_useless_service
	sysctl_config
	sshd_config
	yum_config
	yum_update
	vim_config
	install_docker
	ntpdate_config
else
	$1
fi
