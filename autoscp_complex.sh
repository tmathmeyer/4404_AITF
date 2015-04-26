#!/bin/bash
k="0"

for i in `seq 1 8`;
do
    scp ./sysctl.conf root@10.4.31.$i:/etc/sysctl.conf
    ssh root@10.4.31.$i "sysctl -p"
    ssh root@10.4.31.$i "ip link add link eth0 name aitf type vlan id 100"
    ssh root@10.4.31.$i "mkdir -p /aitf"
    ssh root@10.4.31.$i "apt-get -y install libnetfilter-queue-dev"
    ssh root@10.4.31.$i "apt-get -y install make"
    scp -r ./* root@10.4.31.$i:/aitf
done 

##add addresses on the aitf
ssh root@10.4.31.1 "ip addr add 10.4.31.10/31 dev aitf"
ssh root@10.4.31.2 "ip addr add 10.4.31.20/31 dev aitf"
ssh root@10.4.31.3 "ip addr add 10.4.31.30/31 dev aitf"
ssh root@10.4.31.4 "ip addr add 10.4.31.40/31 dev aitf"

ssh root@10.4.31.5 "ip addr add 10.4.31.21/31 dev aitf"
ssh root@10.4.31.6 "ip addr add 10.4.31.31/31 dev aitf"
ssh root@10.4.31.7 "ip addr add 10.4.31.41/31 dev aitf"
ssh root@10.4.31.8 "ip addr add 10.4.31.42/31 dev aitf"




#host to gatewyas
ssh root@10.4.31.5 "ip route add 10.4.31.10/26 via 10.4.31.20"
ssh root@10.4.31.6 "ip route add 10.4.31.10/26 via 10.4.31.30"
ssh root@10.4.31.7 "ip route add 10.4.31.10/26 via 10.4.31.40"
ssh root@10.4.31.8 "ip route add 10.4.31.10/26 via 10.4.31.40"

##gateways to core / clients
ssh root@10.4.31.2 "ip route add 10.4.31.10/26 via 10.4.31.10"
ssh root@10.4.31.3 "ip route add 10.4.31.10/26 via 10.4.31.10"
ssh root@10.4.31.4 "ip route add 10.4.31.10/26 via 10.4.31.10"

##core outwards
ssh root@10.4.31.1 "ip route add 10.4.31.20/30 via 10.4.31.20"
ssh root@10.4.31.1 "ip route add 10.4.31.30/30 via 10.4.31.30"
ssh root@10.4.31.1 "ip route add 10.4.31.40/29 via 10.4.31.40"

