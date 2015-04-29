#!/bin/bash

iptables -s 10.4.31.0/24 -A INPUT -j NFQUEUE --queue-num 0
iptables -s 10.4.31.0/24 -A FORWARD -j NFQUEUE --queue-num 0
