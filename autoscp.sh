#!/bin/bash

for i in `seq 1 4`;
do
    ssh root@10.4.31.$i "mkdir -p /aitf"
    scp -r ./* root@10.4.31.$i:/aitf
done 

