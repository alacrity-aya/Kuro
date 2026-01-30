#!/bin/bash

NS_NAME=${1:-"test_ns_01"}
HOST_VETH=${2:-"veth_host_01"}

echo "[Cleanup] Cleaning up topology for $NS_NAME..."

PID_FILE="/tmp/iperf_server_${NS_NAME}.pid"
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    echo "[Cleanup] Killing iperf3 server (PID: $PID)"
    kill -9 $PID 2>/dev/null || true
    rm "$PID_FILE"
else
    pkill -F /tmp/iperf_server_${NS_NAME}.pid 2>/dev/null || true
fi

ip netns del $NS_NAME 2>/dev/null || true

ip link delete $HOST_VETH 2>/dev/null || true

echo "[Cleanup] Done."
