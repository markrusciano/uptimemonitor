#!/bin/bash


sudo python3 traceroute_monitor.py \
    --interfaces en0 en1 \
    --target 157.238.230.234 \
    --connection-names "Zentro" "Verizon" \
    --verbose
