#!/bin/bash

for i in `seq 1 4`;
do
    ssh root@10.4.31.$i "mkdir -p /aitf"
    ssh root@10.4.31.$i "apt-get install libnetfilter-queue-dev < yes Y"
    ssh root@10.4.31.$i "apt-get install make"
    scp -r ./* root@10.4.31.$i:/aitf
done 

