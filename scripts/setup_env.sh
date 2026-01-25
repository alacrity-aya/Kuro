#!/bin/bash
set -e

# ================= Configuration =================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLUSTER_NAME="kuro-dev"
IMAGE_NAME="nicolaka/netshoot" 
# IMAGE_NAME="kuro-agent:dev" 

# Flannel & CNI
FLANNEL_URL="https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml"
CNI_PLUGINS_VERSION="v1.3.0"
CNI_ARCHIVE="cni-plugins-linux-amd64-${CNI_PLUGINS_VERSION}.tgz"
CNI_URL="https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/${CNI_ARCHIVE}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'
# ===========================================

setup_proxy_env() {
    if [ -z "$http_proxy" ]; then
        DOCKER_BRIDGE_IP=$(docker network inspect bridge --format='{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || echo "")
        if [ -n "$DOCKER_BRIDGE_IP" ]; then
            echo -e "${YELLOW}Auto-detected Docker Bridge IP: $DOCKER_BRIDGE_IP${NC}"
            export http_proxy="http://$DOCKER_BRIDGE_IP:7890"
            export https_proxy="http://$DOCKER_BRIDGE_IP:7890"
            export no_proxy="localhost,127.0.0.1,$DOCKER_BRIDGE_IP,10.96.0.0/12,10.244.0.0/16,192.168.0.0/16,.svc,.cluster.local"
        fi
    fi
}

setup_infrastructure() {
    echo -e "${GREEN}>>> [Phase 1] Infrastructure Setup${NC}"
    
    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        echo -e "${GREEN}Cluster '${CLUSTER_NAME}' exists.${NC}"
    else
        echo -e "${YELLOW}Creating Cluster '${CLUSTER_NAME}'...${NC}"
        setup_proxy_env
        
        cat <<EOF > /tmp/kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
networking:
  disableDefaultCNI: true
  podSubnet: "10.244.0.0/16"
EOF

        HTTP_PROXY=$http_proxy HTTPS_PROXY=$https_proxy \
        kind create cluster --config /tmp/kind-config.yaml --name "$CLUSTER_NAME"
    fi

    # 1. Download CNI (Host Cache)
    if [ ! -f "/tmp/${CNI_ARCHIVE}" ]; then
        echo "Downloading CNI plugins..."
        curl -L -s "$CNI_URL" -o "/tmp/${CNI_ARCHIVE}"
    fi

    # 2. Configure Nodes
    echo -e "${YELLOW}Configuring Nodes (CNI & Kernel)...${NC}"
    NODES=$(kind get nodes --name "$CLUSTER_NAME")

    for node in $NODES; do
        echo "  > Tuning $node"
        docker cp "/tmp/${CNI_ARCHIVE}" "$node:/root/${CNI_ARCHIVE}"
        
        docker exec "$node" bash -c "mkdir -p /opt/cni/bin && tar -C /opt/cni/bin -xzf /root/${CNI_ARCHIVE}"
        docker exec "$node" bash -c "rm /root/${CNI_ARCHIVE}"
        
        # Kernel settings for networking
        docker exec --privileged "$node" modprobe br_netfilter || true
        docker exec --privileged "$node" sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null
        docker exec --privileged "$node" sysctl -w net.ipv4.ip_forward=1 >/dev/null
    done

    # 3. Install Flannel with Host-GW
    echo -e "${YELLOW}Installing Flannel (host-gw backend)...${NC}"
    curl -sL "$FLANNEL_URL" | \
    sed 's/"Type": "vxlan"/"Type": "host-gw"/' | \
    kubectl apply -f -

    echo "Waiting for Flannel..."
    kubectl rollout status daemonset/kube-flannel-ds -n kube-flannel --timeout=180s
}

deploy_application_with_headless() {
    echo -e "${GREEN}>>> [Phase 2] Deploying Headless Service & Agent${NC}"
    kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null

    kubectl create ns kuro-system --dry-run=client -o yaml | kubectl apply -f -

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: kuro-headless
  namespace: kuro-system
  labels:
    app: kuro-agent
spec:
  clusterIP: None
  selector:
    app: kuro-agent
  ports:
  - port: 80
    name: http
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kuro-agent
  namespace: kuro-system
spec:
  replicas: 2
  selector:
    matchLabels:
      app: kuro-agent
  template:
    metadata:
      labels:
        app: kuro-agent
    spec:
      containers:
      - name: agent
        image: ${IMAGE_NAME}
        command: ["sleep", "infinity"]
        ports:
        - containerPort: 80
EOF

    echo "Waiting for Agents to be ready..."
    kubectl rollout status deployment/kuro-agent -n kuro-system --timeout=60s
}

run_connectivity_test() {
    echo -e "${GREEN}>>> [Phase 3] Running Connectivity Tests (Netshoot)${NC}"
    TEST_NS="kuro-system"
    TEST_POD="netshoot-debug"

    echo "Starting Netshoot pod..."
    kubectl run $TEST_POD -n $TEST_NS --image nicolaka/netshoot --restart=Never -- sleep 3600
    
    echo "Waiting for Netshoot to be ready..."
    kubectl wait --for=condition=Ready pod/$TEST_POD -n $TEST_NS --timeout=60s

    echo -e "${CYAN}--- Test 1: DNS Discovery (Headless) ---${NC}"
    DNS_TARGET="kuro-headless.${TEST_NS}.svc.cluster.local"
    echo "Resolving $DNS_TARGET inside cluster..."
    
    kubectl exec -n $TEST_NS $TEST_POD -- nslookup $DNS_TARGET || {
        echo -e "${RED}DNS Lookup Failed!${NC}"
        exit 1
    }

    echo -e "${CYAN}--- Test 2: Flat Network (Host-GW) Ping ---${NC}"
    POD_IPS=$(kubectl get pods -n $TEST_NS -l app=kuro-agent -o jsonpath='{.items[*].status.podIP}')
    
    for ip in $POD_IPS; do
        echo -n "Pinging Agent at $ip ... "
        kubectl exec -n $TEST_NS $TEST_POD -- ping -c 2 -W 1 $ip >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}SUCCESS${NC}"
        else
            echo -e "${RED}FAILED${NC}"
            echo -e "${RED}Host-GW connectivity issue detected.${NC}"
            exit 1
        fi
    done

    # Cleanup
    echo -e "${YELLOW}Cleaning up test resources...${NC}"
    kubectl delete pod $TEST_POD -n $TEST_NS --force --grace-period=0 >/dev/null 2>&1
}

# ================= Execution =================

setup_infrastructure
deploy_application_with_headless
run_connectivity_test

echo -e "\n${GREEN}>>> All Systems Go! Cluster is running in Host-GW mode.${NC}"
