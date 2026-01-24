#!/bin/bash
set -e

# ================= Configuration =================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLUSTER_NAME="kuro-dev"
IMAGE_NAME="kuro-agent:dev"
AGENT_YAML_PATH="$PROJECT_ROOT/deploy/agent.yaml"
# Flannel Configuration
FLANNEL_MANIFEST="https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml"
CNI_PLUGINS_VERSION="v1.3.0"
CNI_ARCHIVE="cni-plugins-linux-amd64-${CNI_PLUGINS_VERSION}.tgz"
CNI_URL="https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/${CNI_ARCHIVE}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color
# ===========================================

# --- Helper: Detect Proxy ---
setup_proxy_env() {
    # Only attempt to auto-detect if not already set manually
    if [ -z "$http_proxy" ]; then
        DOCKER_BRIDGE_IP=$(docker network inspect bridge --format='{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || echo "")
        if [ -n "$DOCKER_BRIDGE_IP" ]; then
            echo -e "${YELLOW}Auto-detected Docker Bridge IP: $DOCKER_BRIDGE_IP (Assuming proxy at port 7890)${NC}"
            export http_proxy="http://$DOCKER_BRIDGE_IP:7890"
            export https_proxy="http://$DOCKER_BRIDGE_IP:7890"
            export all_proxy="socks5://$DOCKER_BRIDGE_IP:7890"
            export no_proxy="localhost,127.0.0.1,$DOCKER_BRIDGE_IP,10.96.0.0/12,10.244.0.0/16,192.168.0.0/16,.svc,.cluster.local"
        fi
    fi
}

# --- Phase 1: Infrastructure (Cluster & CNI) ---
setup_infrastructure() {
    echo -e "${GREEN}>>> Checking Cluster Status...${NC}"
    
    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        echo -e "${GREEN}Cluster '${CLUSTER_NAME}' already exists. Skipping infrastructure setup.${NC}"
        # Ensure kubectl context is correct even if we skipped creation
        kubectl cluster-info --context "kind-${CLUSTER_NAME}" >/dev/null 2>&1
        return
    fi

    echo -e "${YELLOW}Cluster not found. Starting creation...${NC}"
    setup_proxy_env

    # 1. Create Config
    cat <<EOF > /tmp/kind-flannel.yaml
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

    # 2. Create Cluster
    # Pass proxy vars specifically to the kind command container
    HTTP_PROXY=$http_proxy HTTPS_PROXY=$https_proxy \
    kind create cluster --config /tmp/kind-flannel.yaml --name "$CLUSTER_NAME"

    # 3. Download CNI Plugins ONCE on host (Optimization)
    echo -e "${YELLOW}Downloading CNI plugins (Host cache)...${NC}"
    if [ ! -f "/tmp/${CNI_ARCHIVE}" ]; then
        curl -L -s "$CNI_URL" -o "/tmp/${CNI_ARCHIVE}"
    fi

    # 4. Configure Nodes (CNI Plugins & Kernel Modules)
    echo -e "${YELLOW}Configuring Nodes (CNI & Kernel Modules)...${NC}"
    NODES=$(kind get nodes --name "$CLUSTER_NAME")

    for node in $NODES; do
        echo "  > Processing node: $node"
        
        # Copy cached CNI from host to node
        docker cp "/tmp/${CNI_ARCHIVE}" "$node:/tmp/${CNI_ARCHIVE}"
        
        docker exec "$node" bash -c "mkdir -p /opt/cni/bin && tar -C /opt/cni/bin -xzf /tmp/${CNI_ARCHIVE}"
        docker exec "$node" bash -c "rm /tmp/${CNI_ARCHIVE}"
        
        # Kernel Modules & Sysctl (Robust Setup)
        echo "  > Tuning kernel..."
        docker exec --privileged "$node" modprobe br_netfilter || echo "    (Warning: modprobe br_netfilter failed)"
        docker exec --privileged "$node" modprobe nf_conntrack || true
        docker exec --privileged "$node" sysctl -w net.bridge.bridge-nf-call-iptables=1 || echo "    (Warning: sysctl failed)"
        docker exec "$node" mkdir -p /run/flannel
    done

    # 5. Install Flannel
    echo -e "${YELLOW}Installing Flannel CNI...${NC}"
    kubectl apply -f "$FLANNEL_MANIFEST"
    
    echo "Waiting for Flannel..."
    kubectl rollout status daemonset/kube-flannel-ds -n kube-flannel --timeout=180s
}

# --- Phase 2: Application (Build & Deploy) ---
deploy_application() {
    echo -e "${GREEN}>>> Starting Application Deployment...${NC}"

    # Ensure context is set to the correct cluster
    kubectl config use-context "kind-${CLUSTER_NAME}"

    echo "Setting up Namespaces..."
    kubectl create ns kuro-experiment --dry-run=client -o yaml | kubectl apply -f -
    kubectl create ns kuro-system --dry-run=client -o yaml | kubectl apply -f -

    echo -e "${YELLOW}Building Images...${NC}"
    if [ -f "$PROJECT_ROOT/Makefile" ]; then
        pushd "$PROJECT_ROOT" > /dev/null
        # Assuming 'make images' builds the docker image locally
        make images
        popd > /dev/null
    else
        echo -e "${RED}Error: Makefile not found at $PROJECT_ROOT${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Loading image ($IMAGE_NAME) into Kind...${NC}"
    # This is necessary even if cluster exists, in case image code changed
    kind load docker-image "$IMAGE_NAME" --name "$CLUSTER_NAME"

    echo -e "${YELLOW}Deploying Agent...${NC}"
    if [ -f "$AGENT_YAML_PATH" ]; then
        # Force a restart by deleting pods if DaemonSet exists, 
        # or use rollout restart to pick up the new image we just loaded
        kubectl apply -f "$AGENT_YAML_PATH"
        
        echo "Restarting Agent DaemonSet to pick up new image..."
        kubectl rollout restart daemonset/kuro-agent -n kuro-system
        
        echo "Waiting for Rollout..."
        kubectl rollout status daemonset/kuro-agent -n kuro-system --timeout=60s
    else
        echo -e "${RED}Error: Agent manifest not found at $AGENT_YAML_PATH${NC}"
        exit 1
    fi
}

# ================= Execution Flow =================

setup_infrastructure
deploy_application

echo -e "\n${GREEN}>>> Environment Ready!${NC}"
