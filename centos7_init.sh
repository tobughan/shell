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
	sshd_config                  #配置SSHD
	yum_config                   #配置YUM源
	yum_update                   #安全的自动更新软件包
	vim_config                   #配置VIM编辑器
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
#安装并配置docker-ce
install_docker() {
	yum install -y docker
	cat > /etc/docker/daemon.json <<EOFI
{
  "registry-mirrors": ["https://bm5sgu8k.mirror.aliyuncs.com"],
  "insecure-registries": ["docker.zhuoyuan-info.com"],
  "hosts": ["tcp://0.0.0.0:5555","unix:///var/run/docker.sock"]
}
EOFI
	systemctl daemon-reload
	systemctl restart docker.service
	systemctl enable docker.service
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
	install_docker
	ntpdate_config
else
	$1
fi
