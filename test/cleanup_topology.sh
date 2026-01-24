#!/bin/bash

NS_NAME=${1:-"test_ns_01"}
HOST_VETH=${2:-"veth_host_01"}

echo "[Cleanup] Cleaning up topology for $NS_NAME..."

# 1. 杀死 iperf3 进程
PID_FILE="/tmp/iperf_server_${NS_NAME}.pid"
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    echo "[Cleanup] Killing iperf3 server (PID: $PID)"
    kill -9 $PID 2>/dev/null || true
    rm "$PID_FILE"
else
    # 兜底清理：清理该 netns 下的所有 iperf3
    pkill -F /tmp/iperf_server_${NS_NAME}.pid 2>/dev/null || true
fi

# 2. 删除 Namespace (会自动删除 veth pair 的 pod 端，host 端也会随之消失)
ip netns del $NS_NAME 2>/dev/null || true

# 3. 再次确认删除 Host Veth (双保险)
ip link delete $HOST_VETH 2>/dev/null || true

echo "[Cleanup] Done."
