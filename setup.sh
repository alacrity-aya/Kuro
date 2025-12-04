#!/usr/bin/env bash
set -e

NS_A=hostA
NS_B=hostB

# root-side interfaces
VETH_A_ROOT=veth-a
VETH_B_ROOT=veth-b

# namespace-side interfaces
VETH_A_NS=eth0
VETH_B_NS=eth0

BR=br-sim

IP_A=10.10.0.1/24
IP_B=10.10.0.2/24

echo "[+] Create namespaces"
ip netns add $NS_A
ip netns add $NS_B

echo "[+] Create veth pair for A"
ip link add $VETH_A_ROOT type veth peer name ${VETH_A_NS}
ip link set ${VETH_A_NS} netns $NS_A

echo "[+] Create veth pair for B"
ip link add $VETH_B_ROOT type veth peer name ${VETH_B_NS}
ip link set ${VETH_B_NS} netns $NS_B

echo "[+] Create bridge"
ip link add $BR type bridge
ip link set $BR up

echo "[+] Attach veth root interfaces to bridge"
ip link set $VETH_A_ROOT master $BR
ip link set $VETH_B_ROOT master $BR
ip link set $VETH_A_ROOT up
ip link set $VETH_B_ROOT up

echo "[+] Configure hostA namespace"
ip netns exec $NS_A ip addr add $IP_A dev $VETH_A_NS
ip netns exec $NS_A ip link set $VETH_A_NS up
ip netns exec $NS_A ip link set lo up

echo "[+] Configure hostB namespace"
ip netns exec $NS_B ip addr add $IP_B dev $VETH_B_NS
ip netns exec $NS_B ip link set $VETH_B_NS up
ip netns exec $NS_B ip link set lo up

echo "[+] Test connectivity"
ip netns exec $NS_A ping -c 1 10.10.0.2
