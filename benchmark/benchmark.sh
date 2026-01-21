#!/bin/bash
set -e

# === 配置 ===
NS_SERVER="ns_server"
NS_CLIENT="ns_client"
IP_SERVER="10.0.0.1"
DURATION=20  # 测试持续时间(秒)

# 确保环境已通过你的 setup.sh 初始化
# ./setup.sh 

function cleanup_tc() {
    echo "--- Cleaning up TC rules ---"
    ip netns exec $NS_CLIENT tc qdisc del dev veth_c clsact 2>/dev/null || true
    # 重置为默认 fq (无限制)
    ip netns exec $NS_CLIENT tc qdisc replace dev veth_c root fq
}

function run_iperf() {
    TEST_NAME=$1
    echo "============================================================"
    echo ">>> Running Test: $TEST_NAME"
    echo "============================================================"
    
    # 启动服务端 (后台)
    ip netns exec $NS_SERVER iperf3 -s -1 > /dev/null 2>&1 &
    SERVER_PID=$!
    sleep 1

    # 启动 CPU 监控 (后台)
    # 监控 softirq (si) 和 system (sy) 的 CPU 使用率
    mpstat 1 $((DURATION+1)) > "${TEST_NAME}_cpu.txt" &
    MPSTAT_PID=$!

    # 启动客户端 iperf3
    # -J: JSON 输出以便分析
    # -t: 时间
    # -C: 设置拥塞控制算法为 cubic (标准)
    echo ">>> Starting Traffic..."
    ip netns exec $NS_CLIENT iperf3 -c $IP_SERVER -t $DURATION -J > "${TEST_NAME}_result.json"

    # 等待并清理
    wait $MPSTAT_PID
    kill $SERVER_PID 2>/dev/null || true
    
    # 解析结果
    echo ">>> Analysis for $TEST_NAME:"
    BITS_PER_SEC=$(jq '.end.sum_sent.bits_per_second' "${TEST_NAME}_result.json")
    RETRANSMITS=$(jq '.end.sum_sent.retransmits' "${TEST_NAME}_result.json")
    CPU_AVG=$(awk '/Average/ {print "User: "$3"% System: "$5"% SoftIRQ: "$9"%"}' "${TEST_NAME}_cpu.txt")
    
    # 转换 bps 为 Mbps
    MBPS=$(echo "$BITS_PER_SEC / 1000000" | bc -l)
    
    printf "  Throughput:    %.2f Mbps\n" "$MBPS"
    printf "  Retransmits:   %d\n" "$RETRANSMITS"
    printf "  CPU Usage:     %s\n\n" "$CPU_AVG"
}

# 确保 jq 已安装
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please run 'apt install jq' or 'yum install jq'"
    exit 1
fi

# ==========================================
# 1. 基准测试 (Baseline - No Limit)
# ==========================================
cleanup_tc
run_iperf "01_baseline_nolimit"

# ==========================================
# 2. 你的 eBPF 程序
# ==========================================
cleanup_tc
echo ">>> Starting your Go eBPF program (background)..."
# 编译并运行你的 Go 程序
go build -o ebpf_shaper main.go
./ebpf_shaper > ebpf_log.txt 2>&1 &
GO_PID=$!

# 等待 eBPF 加载
sleep 2
# 检查是否挂载成功
if ! ip netns exec $NS_CLIENT tc filter show dev veth_c egress | grep -q "simple_edt"; then
    echo "ERROR: eBPF filter not attached!"
    kill $GO_PID
    exit 1
fi

run_iperf "02_ebpf_custom"

# 停止 Go 程序
kill -SIGINT $GO_PID
wait $GO_PID 2>/dev/null || true

# ==========================================
# 3. 原生 TC FQ Maxrate
# ==========================================
cleanup_tc
echo ">>> Applying Native TC FQ Limit (100Mbps)..."
# ip netns exec $NS_CLIENT tc qdisc replace dev veth_c root fq maxrate 100mbit
ip netns exec $NS_CLIENT tc qdisc replace dev veth_c root fq maxrate 100mbit flow_limit 420

run_iperf "03_native_tc_fq"

# ==========================================
# 4. 原生 TC TBF (可选对比)
# ==========================================
cleanup_tc
echo ">>> Applying Native TC TBF Limit (100Mbps)..."
ip netns exec $NS_CLIENT tc qdisc replace dev veth_c root tbf rate 100mbit burst 32kbit latency 50ms

run_iperf "04_native_tc_tbf"

echo ">>> All tests done."
