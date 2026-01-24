#!/bin/bash
set -e

# 参数定义
NS_NAME=${1:-"test_ns_01"}
HOST_VETH=${2:-"veth_host_01"}
POD_VETH=${3:-"veth_pod_01"} # 在 Pod 内部通常重命名为 eth0，这里为了清晰先保留名字，脚本里会改
POD_IP=${4:-"10.20.1.2/24"}
HOST_IP_GW=${5:-"10.20.1.1/24"}
IPERF_PORT=${6:-5201}

# 1. 清理旧环境 (防止残留)
ip netns del $NS_NAME 2>/dev/null || true
ip link delete $HOST_VETH 2>/dev/null || true

echo "[Setup] Creating Namespace: $NS_NAME"
ip netns add $NS_NAME

echo "[Setup] Creating Veth Pair: $HOST_VETH <--> $POD_VETH"
ip link add $HOST_VETH type veth peer name $POD_VETH

echo "[Setup] Moving $POD_VETH to namespace $NS_NAME and renaming to eth0"
ip link set $POD_VETH netns $NS_NAME
ip netns exec $NS_NAME ip link set dev $POD_VETH name eth0

echo "[Setup] Configuring IPs"
# Host side
ip addr add $HOST_IP_GW dev $HOST_VETH
ip link set $HOST_VETH up

# Pod side
ip netns exec $NS_NAME ip addr add $POD_IP dev eth0
ip netns exec $NS_NAME ip link set eth0 up
ip netns exec $NS_NAME ip link set lo up
ip netns exec $NS_NAME ip route add default via ${HOST_IP_GW%%/*}

# 2. 简单的连通性测试 (Ping)
echo "[Setup] Testing Connectivity (Ping)..."
# 等待链路建立
sleep 1
if ping -c 1 -W 1 ${POD_IP%%/*} > /dev/null; then
    echo "[Setup] Ping SUCCESS: Host -> Pod"
else
    echo "[Setup] Ping FAILED: Host -> Pod"
    exit 1
fi

# 3. 启动 iperf3 Server (后台运行)
echo "[Setup] Starting iperf3 server inside Netns..."
LOG_FILE="/tmp/iperf_server_${NS_NAME}.log"

# 使用 nohup 且重定向标准输出和错误到日志文件
nohup ip netns exec $NS_NAME iperf3 -s -p $IPERF_PORT --logfile $LOG_FILE > /dev/null 2>&1 &
echo $! > /tmp/iperf_server_${NS_NAME}.pid

# 给服务一点启动时间
sleep 2

# 检查进程是否存活
if ! kill -0 $(cat /tmp/iperf_server_${NS_NAME}.pid) 2>/dev/null; then
    echo "[Setup] CRITICAL: iperf3 server failed to start! Check logs:"
    cat $LOG_FILE
    exit 1
fi

echo "[Setup] Topology Ready. Server PID: $(cat /tmp/iperf_server_${NS_NAME}.pid)"
echo "[Setup] Server Logs at: $LOG_FILE"
