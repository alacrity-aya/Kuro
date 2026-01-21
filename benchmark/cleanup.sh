#!/bin/bash
ip netns del ns_server 2>/dev/null || true
ip netns del ns_client 2>/dev/null || true
sudo rm -f *.txt *.json
echo ">>> Environment Cleaned."
