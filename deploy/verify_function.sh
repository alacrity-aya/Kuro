#!/bin/bash

AGENT_NS="kuro-system"
TARGET_NS="kuro-experiment"
TEST_POD_NAME="verify-pod-$(date +%s)"

echo "Streaming logs..."
kubectl logs -f -l app=kuro-agent -n $AGENT_NS --max-log-requests=10 | grep --line-buffered -A 5 -E "\[Watcher\]|\[Debug Audit\]" &
LOG_PID=$!

trap "kill $LOG_PID" EXIT

sleep 2

echo "Creating Pod $TEST_POD_NAME..."
kubectl run $TEST_POD_NAME --image=nginx:alpine -n $TARGET_NS --restart=Never

kubectl wait --for=condition=Ready pod/$TEST_POD_NAME -n $TARGET_NS --timeout=30s

echo "Holding for observation..."
sleep 10

echo "Deleting Pod $TEST_POD_NAME..."
kubectl delete pod $TEST_POD_NAME -n $TARGET_NS --grace-period=0 --force

echo "Waiting for cleanup logs..."
sleep 5

echo "Done."
