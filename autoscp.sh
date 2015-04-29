#!/bin/bash

for i in `seq 1 4`;
do
    scp ./sysctl.conf root@10.4.31.$i:/etc/sysctl.conf
    ssh root@10.4.31.$i "sysctl -p"
    ssh root@10.4.31.$i "ip link add link eth0 name aitf type vlan id 100"
    ssh root@10.4.31.$i "mkdir -p /aitf"
    ssh root@10.4.31.$i "apt-get -y install libnetfilter-queue-dev"
    ssh root@10.4.31.$i "apt-get -y install make"
    ssh root@10.4.31.$i "apt-get -y update"
    ssh root@10.4.31.$i "apt-get -y install libssl-dev"
    scp -r ./* root@10.4.31.$i:/aitf
done 

##add addresses on the aitf
ssh root@10.4.31.1 "ip addr add 10.4.31.129/32 dev aitf" &
ssh root@10.4.31.2 "ip addr add 10.4.31.128/32 dev aitf" &

ssh root@10.4.31.3 "ip addr add 10.4.31.196/32 dev aitf" &
ssh root@10.4.31.4 "ip addr add 10.4.31.197/32 dev aitf" &



ssh root@10.4.31.1 "ip route add 10.4.31.196/31 via 10.4.31.128" &
ssh root@10.4.31.2 "ip route add 10.4.31.196/31 via 10.4.31.196" &

ssh root@10.4.31.3 "ip route add 10.4.31.128/31 via 10.4.31.128" &
ssh root@10.4.31.4 "ip route add 10.4.31.128/31 via 10.4.31.196" &
