#!/bin/bash

iptables -A INPUT -j NFQUEUE --queue-num 0
iptables -A FORWARD -j NFQUEUE --queue-num 0
