#!/bin/bash

#运行环境
printf "\n**************************Kernel&OS***************************\n"
uname -a 
cat /etc/redhat-release


printf "\n**************************GLIBC*******************************\n"
/lib64/libc*.so

printf "\n**************************hostname*******************************\n"
hostname -a

printf "\n**************************/etc/resolv.conf*******************************\n"
cat /etc/resolv.conf

printf "\n**************************Installed RPM*******************************\n"
rpm -qa


#时间信息
printf "\n**************************uptime*******************************\n"
uptime
printf "\n**************************date*******************************\n"
date
printf "\n**************************NTP is running?*******************************\n"
ntpdate 2>&1 | grep "no servers"
if [ $? -eq 0 ]; then
  echo "It's not work on NTP"
else
  echo "It's work on NTP"
fi

#用户信息
printf "\n**************************User*******************************\n"
whoami


#环境变量
printf "\n**************************env*******************************\n"
env

printf "\n**************************rc.local*******************************\n"
cat /etc/rc.local



#硬件信息
#硬盘&分区信息
printf "\n**************************Fdisk*******************************\n"
fdisk -l 

printf "\n**************************Mount*******************************\n"
mount

printf "\n**************************Disk Usage*******************************\n"
df -h

printf "\n**************************Block Device*******************************\n"
lsblk -a

#CPU信息
#printf "\n**************************CPU Device(/proc/cpuinfo)*******************************\n"
#cat /proc/cpuinfo
printf "\n**************************CPU Device(lscpu)*******************************\n"
lscpu

printf "\n**************************CPU Summary*******************************\n"
function get_nr_processor()
{
    grep '^processor' /proc/cpuinfo | wc -l
}
function get_nr_socket()
{
    grep 'physical id' /proc/cpuinfo | awk -F: '{
            print $2 | "sort -un"}' | wc -l
}
function get_nr_siblings()
{
    grep 'siblings' /proc/cpuinfo | awk -F: '{
            print $2 | "sort -un"}'
}
function get_nr_cores_of_socket()
{
    grep 'cpu cores' /proc/cpuinfo | awk -F: '{
            print $2 | "sort -un"}'
}
echo '===== CPU Topology Table ====='
echo
echo '+--------------+---------+-----------+'
echo '| Processor ID | Core ID | Socket ID |'
echo '+--------------+---------+-----------+'
while read line; do
    if [ -z "$line" ]; then
        printf '| %-12s | %-7s | %-9s |\n' $p_id $c_id $s_id
        echo '+--------------+---------+-----------+'
        continue
    fi

    if echo "$line" | grep -q "^processor"; then
        p_id=`echo "$line" | awk -F: '{print $2}' | tr -d ' '`
    fi

    if echo "$line" | grep -q "^core id"; then
        c_id=`echo "$line" | awk -F: '{print $2}' | tr -d ' '`
    fi

    if echo "$line" | grep -q "^physical id"; then
        s_id=`echo "$line" | awk -F: '{print $2}' | tr -d ' '`
    fi

done < /proc/cpuinfo
echo

awk -F: '{
    if ($1 ~ /processor/) {
        gsub(/ /,"",$2);
        p_id=$2;
    } else if ($1 ~ /physical id/){
        gsub(/ /,"",$2);
        s_id=$2;
        arr[s_id]=arr[s_id] " " p_id
    }
}

END{
    for (i in arr)
        printf "Socket %s:%s\n", i, arr[i];
}' /proc/cpuinfo
echo
echo '===== CPU Info Summary ====='
nr_processor=`get_nr_processor`
echo "Logical processors: $nr_processor"
nr_socket=`get_nr_socket`
echo "Physical socket: $nr_socket"
nr_siblings=`get_nr_siblings`
echo "Siblings in one socket: $nr_siblings"
nr_cores=`get_nr_cores_of_socket`
echo "Cores in one socket: $nr_cores"
let nr_cores*=nr_socket
echo "Cores in total: $nr_cores"
if [ "$nr_cores" = "$nr_processor" ]; then
    echo "Hyper-Threading: off"
else
    echo "Hyper-Threading: on"
fi

echo

printf "\n**************************Memory Usage*******************************\n"
free -m

printf "\n**************************Memory info*******************************\n"
cat /proc/meminfo

printf "\n**************************Dmi info*******************************\n"
dmidecode -t system 

printf "\n**************************ifconfig*******************************\n"
ifconfig -a

printf "\n**************************ip addr*******************************\n"
ip addr

printf "\n**************************ip route*******************************\n"
ip route

printf "\n**************************ethtool*******************************\n"
niclist=`ip -o link show | awk -F': ' '{print $2}'`
for nic in ${niclist};do
  echo "========$nic============"
  ethtool $nic
  ethtool -S $nic
done

printf "\n**************************PCI Device(Network)*******************************\n"
lspci -nn -v -d ::0200

printf "\n**************************netstat -s*******************************\n"
netstat -s

printf "\n**************************netstat -a*******************************\n"
netstat -a

#进程
printf "\n**************************Processes*******************************\n"
ps -aux

#服务
printf "\n**************************Systemd*******************************\n"
systemctl status --no-pager  -a

printf "\n**************************iptable*******************************\n"
iptables -L


#设备名
printf "\n**************************devlist*******************************\n"
ls /dev/*

#日志
printf "\n**************************/var/log/message(last 1000 lines)*******************************\n"
tail -n 1000 /var/log/messages

printf "\n**************************dmesg(last 1000 lines)*******************************\n"
dmesg  | tail -n 1000 

#目录
printf "\n**************************Directory*******************************\n"
echo ""
echo "Check/opt"
ls -lR /opt 
echo ""
echo "Check /usr/local/share/tomcat/"
ls -l /usr/local/share/tomcat/
echo ""
echo "Check /usr/local/share/gwcfg/"
ls -l /usr/local/share/gwcfg/
echo ""
echo "Check /boot"
ls -l /boot

#网关
printf "\n**************************Numa*******************************\n"
ls /sys/devices/system/node/node0/hugepages/ 
ls /sys/devices/system/node/node1/hugepages/
ls /sys/devices/system/node/node2/hugepages/
ls /sys/devices/system/node/node3/hugepages/
ls /sys/devices/system/node/node4/hugepages/
ls /sys/devices/system/node/node5/hugepages/
ls /sys/devices/system/node/node6/hugepages/
ls /sys/devices/system/node/node7/hugepages/

printf "\n**************************dpdk-devbind.py*******************************\n"
python /opt/apigw/gwhw/tools/dpdk-devbind.py --status

printf "\n**************************Check gw_parser*******************************\n"
ps aux | grep gw_parser


