#!/bin/bash

ip addr add 10.0.3.15/24 dev toto0 
ifconfig toto0 up
route add -net 10.0.3.0 netmask 255.255.255.0 dev toto0
route add -net 192.168.16.0 netmask 255.255.255.0 dev toto0
route add -net 192.168.15.0 netmask 255.255.255.0 dev eth13
sysctl -w net.ipv4.ip_forward=1