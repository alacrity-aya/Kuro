#!/usr/bin/env bash
set -e

NS_A="hostA"
NS_B="hostB"

BR="br-sim"

echo "[+] Deleting namespaces..."
ip netns del $NS_A 2>/dev/null || true
ip netns del $NS_B 2>/dev/null || true

echo "[+] Deleting bridge..."
ip link del $BR 2>/dev/null || true

echo "[+] Cleanup done."
