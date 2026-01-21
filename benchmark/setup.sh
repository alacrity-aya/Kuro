#!/bin/bash
set -e

NS_SERVER="ns_server"
NS_CLIENT="ns_client"
VETH_SERVER="veth_s"
VETH_CLIENT="veth_c"
IP_SERVER="10.0.0.1/24"
IP_CLIENT="10.0.0.2/24"

bash ./cleanup.sh

echo ">>> Creating Namespaces..."
ip netns add $NS_SERVER
ip netns add $NS_CLIENT

echo ">>> Creating Veth Pair..."
ip link add $VETH_SERVER type veth peer name $VETH_CLIENT

echo ">>> Moving Interfaces..."
ip link set $VETH_SERVER netns $NS_SERVER
ip link set $VETH_CLIENT netns $NS_CLIENT

echo ">>> Configuring IPs and UP..."
# Server Side
ip netns exec $NS_SERVER ip addr add $IP_SERVER dev $VETH_SERVER
ip netns exec $NS_SERVER ip link set $VETH_SERVER up
ip netns exec $NS_SERVER ip link set lo up
# Client Side
ip netns exec $NS_CLIENT ip addr add $IP_CLIENT dev $VETH_CLIENT
ip netns exec $NS_CLIENT ip link set $VETH_CLIENT up
ip netns exec $NS_CLIENT ip link set lo up

echo ">>> [IMPORTANT] Setting FQ Qdisc for EDT..."
# 这一点至关重要！没有 fq，skb->tstamp 将被忽略
ip netns exec $NS_CLIENT tc qdisc replace dev $VETH_CLIENT root fq

echo ">>> Environment Ready!"
echo "    Server IP: 10.0.0.1 (in $NS_SERVER)"
echo "    Client IP: 10.0.0.2 (in $NS_CLIENT)"
echo "    Run iperf server:  ip netns exec $NS_SERVER iperf3 -s"
