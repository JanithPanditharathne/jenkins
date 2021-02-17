#!/bin/bash +x

set -e

# Falcon Initial Server Setup
# Yasitha Bogamuwa

# ===================================================================
# CONFIG - Only edit the below lines to setup the script
# ===================================================================

# COLOR CODES
COLOR_OFF='\033[0m'
IYELLOW='\033[0;93m'
CYAN='\033[0;36m'
IRED='\033[0;91m'

# ===================================================================
# FUNCTIONS START HERE
# ===================================================================

checkOS()
{
	printf "${CYAN}-- Checking Operating System (OS) compatibility ${COLOR_OFF}\n\n"

	# Find OS name and the Version ID
	if [ -f /etc/os-release ]; then

		# Get OS_ID and VERSION_ID
		OS_ID=$(awk -F= '$1=="ID" { print $2 ;}' /etc/os-release | xargs)
		VERSION_ID=$(awk -F= '$1=="VERSION_ID" { print $2 ;}' /etc/os-release | xargs | awk -F '.' '{print $1}')

		# Check if the OS is CentOS 7/8
		if [[ ${OS_ID} -ne "centos" || ( ${VERSION_ID} -ne "7" && ${VERSION_ID} -ne "8" ) ]]; then
			printf "${IRED}\t ERROR: Unsupported Operating System. For CentOS 7/8 x64 systems ONLY! ${COLOR_OFF}\n\n"
			exit 1
		fi

	else
		printf "${IRED}\t ERROR: Unsupported Operating System. For CentOS 7/8 x64 systems ONLY! ${COLOR_OFF}\n\n"
		exit 1
	fi
}

checkRoot()
{
	printf "${CYAN}-- Checking if the script is being executed as root user ${COLOR_OFF}\n\n"

	# Check if the script is being executed as root
	if [[ ${EUID} -ne 0 ]]; then
		printf "${IRED}\t ERROR: This script must be run as root! ${COLOR_OFF}\n\n"
		exit 1
	fi
}

osUpdates()
{
	printf "${CYAN}-- Installing prerequisites ${COLOR_OFF}\n\n"

	# Check if the OS is CentOS 7
	if [[ ${OS_ID} -eq "centos" && ${VERSION_ID} -eq "7" ]]; then

		# Install necessary GPG Keys
		sudo rpm --import http://vault.centos.org/RPM-GPG-KEY-CentOS-7

		# Cleanup local YUM cache
		sudo yum clean all -q > /dev/null

		# Install prerequisites
		sudo yum install --nogpgcheck -y -q dnf vim tmux yum-utils dnf-automatic policycoreutils-python 'dnf-command(config-manager)' > /dev/null
		
		# Enable automatic security updates
		sudo sed -i 's,^upgrade_type =.*$,upgrade_type = security,' /etc/dnf/automatic.conf
		sudo sed -i 's,^apply_updates =.*$,apply_updates = yes,' /etc/dnf/automatic.conf

		# Exclude kernel upgrades
		grep -qxF 'exclude = kernel*' /etc/dnf/automatic.conf || echo -e "\n# Exclude Kernel Upgrades \nexclude = kernel*" | sudo tee -a /etc/dnf/automatic.conf > /dev/null

		# start and enable dnf-automatic.timer
		sudo systemctl --quiet enable --now dnf-automatic.timer

	# Check if the OS is CentOS 8
	elif [[ ${OS_ID} -eq "centos" && ${VERSION_ID} -eq "8" ]]; then

		# Install necessary GPG Keys
		sudo rpm --import https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official

		# Cleanup local DNF cache
		sudo dnf clean all -q > /dev/null

		# Install prerequisites
		sudo dnf install --nogpgcheck -y -q vim tmux yum-utils dnf-automatic policycoreutils-python-utils 'dnf-command(config-manager)' > /dev/null
		
		# Enable automatic security updates
		sudo sed -i 's,^upgrade_type =.*$,upgrade_type = security,' /etc/dnf/automatic.conf
		sudo sed -i 's,^apply_updates =.*$,apply_updates = yes,' /etc/dnf/automatic.conf

		# Exclude kernel upgrades
		grep -qxF 'exclude = kernel*' /etc/dnf/automatic.conf || echo -e "\n# Exclude Kernel Upgrades \nexclude = kernel*" | sudo tee -a /etc/dnf/automatic.conf > /dev/null

		# start and enable dnf-automatic.timer
		sudo systemctl --quiet enable --now dnf-automatic.timer

	# Unsupported Operating System
	else
		printf "${IRED}\t ERROR: Unsupported Operating System. For CentOS 7/8 x64 systems ONLY! ${COLOR_OFF}\n\n"
		exit 1
	fi
}

osTweeks()
{

printf "${CYAN}-- Applying OS tweeks ${COLOR_OFF}\n\n"
	
# Set Server Time Zone
sudo timedatectl set-timezone Asia/Colombo

# Disable IPv6
sudo sed -i '/::1/d' /etc/hosts

# Load overlay and br_netfilter kernel modules during boot
cat <<EOF | sudo tee /etc/modules-load.d/containerd.conf > /dev/null
overlay
br_netfilter
EOF

# Add overlay and br_netfilter kernel modules to the Linux kernel
modprobe overlay
modprobe br_netfilter

# Updating kernel parameter settings
cat <<EOF | sudo tee /etc/sysctl.d/00-sysctl.conf > /dev/null
#############################################################################################
# Tweak virtual memory
#############################################################################################

# Default: 30
# 0 - Never swap under any circumstances.
# 1 - Do not swap unless there is an out-of-memory (OOM) condition.
vm.swappiness = 10

# vm.dirty_background_ratio is used to adjust how the kernel handles dirty pages that must be flushed to disk.
# Default value is 10.
# The value is a percentage of the total amount of system memory, and setting this value to 5 is appropriate in many situations.
# This setting should not be set to zero.
vm.dirty_background_ratio = 10

# The total number of dirty pages that are allowed before the kernel forces synchronous operations to flush them to disk
# can also be increased by changing the value of vm.dirty_ratio, increasing it to above the default of 30 (also a percentage of total system memory)
# vm.dirty_ratio value in-between 60 and 80 is a reasonable number.
vm.dirty_ratio = 60

# vm.max_map_count will calculate the current number of memory mapped files.
# The minimum value for mmap limit (vm.max_map_count) is the number of open files ulimit (cat /proc/sys/fs/file-max).
# map_count should be around 1 per 128 KB of system memory. Therefore, max_map_count will be 262144 on a 32 GB system.
# Default: 65530
vm.max_map_count = 2097152

#############################################################################################
# Tweak file handles
#############################################################################################

# Increases the size of file handles and inode cache and restricts core dumps.
fs.file-max = 2097152
fs.suid_dumpable = 0

#############################################################################################
# Tweak network settings
#############################################################################################

# Default amount of memory allocated for the send and receive buffers for each socket.
# This will significantly increase performance for large transfers.
net.core.wmem_default = 25165824
net.core.rmem_default = 25165824

# Maximum amount of memory allocated for the send and receive buffers for each socket.
# This will significantly increase performance for large transfers.
net.core.wmem_max = 25165824
net.core.rmem_max = 25165824

# In addition to the socket settings, the send and receive buffer sizes for
# TCP sockets must be set separately using the net.ipv4.tcp_wmem and net.ipv4.tcp_rmem parameters.
# These are set using three space-separated integers that specify the minimum, default, and maximum sizes, respectively.
# The maximum size cannot be larger than the values specified for all sockets using net.core.wmem_max and net.core.rmem_max.
# A reasonable setting is a 4 KiB minimum, 64 KiB default, and 2 MiB maximum buffer.
net.ipv4.tcp_wmem = 20480 12582912 25165824
net.ipv4.tcp_rmem = 20480 12582912 25165824

# Increase the maximum total buffer-space allocatable
# This is measured in units of pages (4096 bytes)
net.ipv4.tcp_mem = 65536 25165824 262144
net.ipv4.udp_mem = 65536 25165824 262144

# Minimum amount of memory allocated for the send and receive buffers for each socket.
net.ipv4.udp_wmem_min = 16384
net.ipv4.udp_rmem_min = 16384

# Enabling TCP window scaling by setting net.ipv4.tcp_window_scaling to 1 will allow
# clients to transfer data more efficiently, and allow that data to be buffered on the broker side.
net.ipv4.tcp_window_scaling = 1

# Increasing the value of net.ipv4.tcp_max_syn_backlog above the default of 1024 will allow
# a greater number of simultaneous connections to be accepted.
net.ipv4.tcp_max_syn_backlog = 10240

# Increasing the value of net.core.netdev_max_backlog to greater than the default of 1000
# can assist with bursts of network traffic, specifically when using multigigabit network connection speeds,
# by allowing more packets to be queued for the kernel to process them.
net.core.netdev_max_backlog = 65536

# Increase the maximum amount of option memory buffers
net.core.optmem_max = 25165824

# Number of times SYNACKs for passive TCP connection.
net.ipv4.tcp_synack_retries = 2

# Allowed local port range.
net.ipv4.ip_local_port_range = 2048 65535

# Protect Against TCP Time-Wait
# Default: net.ipv4.tcp_rfc1337 = 0
net.ipv4.tcp_rfc1337 = 1

# Decrease the time default value for tcp_fin_timeout connection
net.ipv4.tcp_fin_timeout = 15

# The maximum number of backlogged sockets.
# Default is 128.
net.core.somaxconn = 4096

# Turn on syncookies for SYN flood attack protection.
net.ipv4.tcp_syncookies = 1

# Avoid a smurf attack
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Turn on protection for bad icmp error messages
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable automatic window scaling.
# This will allow the TCP buffer to grow beyond its usual maximum of 64K if the latency justifies it.
net.ipv4.tcp_window_scaling = 1

# Turn on and log spoofed, source routed, and redirect packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Tells the kernel how many TCP sockets that are not attached to any
# user file handle to maintain. In case this number is exceeded,
# orphaned connections are immediately reset and a warning is printed.
# Default: net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_max_orphans = 65536

# Do not cache metrics on closing connections
net.ipv4.tcp_no_metrics_save = 1

# Enable timestamps as defined in RFC1323:
# Default: net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_timestamps = 1

# Enable select acknowledgments.
# Default: net.ipv4.tcp_sack = 1
net.ipv4.tcp_sack = 1

# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks.
# net.ipv4.tcp_tw_recycle has been removed from Linux 4.12. Use net.ipv4.tcp_tw_reuse instead.
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_reuse = 1

# The accept_source_route option causes network interfaces to accept packets with the Strict Source Route (SSR) or Loose Source Routing (LSR) option set. 
# The following setting will drop packets with the SSR or LSR option set.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Turn on reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Disables sending of all IPv4 ICMP redirected packets.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

#############################################################################################
# Docker related settings
#############################################################################################

# Enable IP forwarding.
# IP forwarding is the ability for an operating system to accept incoming network packets on one interface,
# recognize that it is not meant for the system itself, but that it should be passed on to another network, and then forwards it accordingly.
net.ipv4.ip_forward = 1

# These settings control if packets traversing a network bridge are processed by iptables rules on the host system.
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1

#############################################################################################
# Tweak kernel parameters
#############################################################################################

# Address Space Layout Randomization (ASLR) is a memory-protection process for operating systems that guards against buffer-overflow attacks.
# It helps to ensure that the memory addresses associated with running processes on systems are not predictable,
# thus flaws or vulnerabilities associated with these processes will be more difficult to exploit.
# Accepted values: 0 = Disabled, 1 = Conservative Randomization, 2 = Full Randomization
kernel.randomize_va_space = 2

# Allow for more PIDs (to reduce rollover problems)
kernel.pid_max = 65536
EOF

# Apply kernel parameter chnages
sudo sysctl -p /etc/sysctl.d/00-sysctl.conf > /dev/null
	
}

disableTHP()
{

printf "${CYAN}-- Disabling Transparent Huge Pages (THP) ${COLOR_OFF}\n\n"

# Disable Transparent Huge Pages (THP)
cat <<EOF | sudo tee /etc/systemd/system/disable-thp.service > /dev/null
[Unit]
Description=Disable Transparent Huge Pages (THP)

[Service]
Type=simple
ExecStart=/bin/sh -c "echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled && echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag"

[Install]
WantedBy=multi-user.target
EOF

# Start and enable Disable THP service
sudo systemctl daemon-reload
sudo systemctl --quiet enable --now disable-thp

}

setupDocker()
{
	printf "${CYAN}-- Installing the latest version of Docker ${COLOR_OFF}\n\n"

	# Check if the OS is CentOS 7
	if [[ ${OS_ID} -eq "centos" && ${VERSION_ID} -eq "7" ]]; then

		# Install prerequisites
		sudo dnf install --nogpgcheck -y -q device-mapper-persistent-data lvm2 > /dev/null

		# Add Docker CE repository
		sudo dnf config-manager -y -q --add-repo https://download.docker.com/linux/centos/docker-ce.repo > /dev/null
	
		# Install Docker CE
		sudo dnf install --nogpgcheck -y -q docker-ce docker-ce-cli > /dev/null

	# Check if the OS is CentOS 8
	elif [[ ${OS_ID} -eq "centos" && ${VERSION_ID} -eq "8" ]]; then

		# Install prerequisites
		sudo dnf install --nogpgcheck -y -q device-mapper-persistent-data lvm2 > /dev/null

		# Add Docker CE repository
		sudo dnf config-manager -y -q --add-repo https://download.docker.com/linux/centos/docker-ce.repo > /dev/null

		# Install Docker CE
		sudo dnf install --nogpgcheck -y -q https://download.docker.com/linux/centos/7/x86_64/stable/Packages/containerd.io-1.2.6-3.3.el7.x86_64.rpm > /dev/null
		sudo dnf install --nogpgcheck -y -q docker-ce docker-ce-cli > /dev/null

	# Unsupported Operating System
	else
		printf "${IRED}\t ERROR: Unsupported Operating System. For CentOS 7/8 x64 systems ONLY! ${COLOR_OFF}\n\n"
		exit 1
	fi

# Change default control group (cgroup) driver to systemd and setup log rotation
mkdir -p /etc/docker
cat <<EOF | sudo tee /etc/docker/daemon.json > /dev/null
{
	"exec-opts": ["native.cgroupdriver=systemd"],
	"log-driver": "json-file",
	"log-opts": {
		"max-size": "10m",
		"max-file": "10"
	},
	"storage-driver": "overlay2",
	"storage-opts": [
		"overlay2.override_kernel_check=true"
	]
}
EOF

# Start and enable docker service
sudo systemctl --quiet enable --now docker

}

initSwarm()
{

	printf "${CYAN}-- Initializing a swarm ${COLOR_OFF}\n\n"

	# Initialize a swarm
	if [ "$(docker info --format '{{.Swarm.LocalNodeState}}')" == "inactive" ]; then
		docker swarm init > /dev/null
	else
		printf "${IYELLOW}\t This node is already part of a swarm! ${COLOR_OFF}\n\n"
	fi

}

# ===================================================================
# MAIN BODY STARTS HERE
# ===================================================================

echo -e "-- ------------------ -- \n"
echo -e "-- BEGIN BOOTSTRAPING -- \n"
echo -e "-- ------------------ -- \n"

checkOS
checkRoot
osUpdates
osTweeks
disableTHP
setupDocker
initSwarm

echo -e "-- ---------------- -- \n"
echo -e "-- END BOOTSTRAPING -- \n"
echo -e "-- ---------------- -- \n"

