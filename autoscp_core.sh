#!/bin/bash

for i in `seq 1 5`;
do
    scp ./sysctl.conf root@10.4.31.$i:/etc/sysctl.conf
    ssh root@10.4.31.$i "sysctl -p"
    ssh root@10.4.31.$i "mkdir -p /aitf"
    ssh root@10.4.31.$i "apt-get -y install libnetfilter-queue-dev"
    ssh root@10.4.31.$i "apt-get -y install make"
    ssh root@10.4.31.$i "apt-get -y update"
    ssh root@10.4.31.$i "apt-get -y install libssl-dev"
    scp -r ./* root@10.4.31.$i:/aitf
done 



##add addresses on the aitf





ssh root@10.4.31.1 "ip route add 10.4.31.3/32 via 10.4.31.2" &
ssh root@10.4.31.1 "ip route add 10.4.31.4/32 via 10.4.31.2" &
ssh root@10.4.31.1 "ip route add 10.4.31.5/32 via 10.4.31.2" &

ssh root@10.4.31.2 "ip route add 10.4.31.4/32 via 10.4.31.3" &
ssh root@10.4.31.2 "ip route add 10.4.31.5/32 via 10.4.31.3" &

ssh root@10.4.31.3 "ip route add 10.4.31.1/32 via 10.4.31.2" &
ssh root@10.4.31.3 "ip route add 10.4.31.5/32 via 10.4.31.4" &

ssh root@10.4.31.4 "ip route add 10.4.31.1/32 via 10.4.31.3" &
ssh root@10.4.31.4 "ip route add 10.4.31.2/32 via 10.4.31.3" &

ssh root@10.4.31.5 "ip route add 10.4.31.1/32 via 10.4.31.4" &
ssh root@10.4.31.5 "ip route add 10.4.31.2/32 via 10.4.31.4" &
ssh root@10.4.31.5 "ip route add 10.4.31.3/32 via 10.4.31.4" &



