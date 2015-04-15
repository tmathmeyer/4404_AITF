#!/bin/bash

iptables -A INPUT -j NFQUEUE --queue-num 0
