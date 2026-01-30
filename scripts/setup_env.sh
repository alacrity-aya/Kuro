#!/bin/bash
set -e

# ================= Configuration =================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLUSTER_NAME="kuro-dev"
AGENT_IMAGE_NAME="kuro-agent:dev" 
CONTROLLER_IMAGE_NAME="kuro-controller:dev" 

AGENT_YAML_PATH="$PROJECT_ROOT/deploy/agent.yaml"
CONTROLLER_YAML_PATH="$PROJECT_ROOT/deploy/controller.yaml"

# Flannel & CNI
FLANNEL_URL="https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml"
CNI_PLUGINS_VERSION="v1.3.0"
CNI_ARCHIVE="cni-plugins-linux-amd64-${CNI_PLUGINS_VERSION}.tgz"
CNI_URL="https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/${CNI_ARCHIVE}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# ===========================================

parse_args() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -h|--help) echo "Usage: $0"; exit 0 ;;
            *) echo -e "${RED}Unknown: $1${NC}"; exit 1 ;;
        esac
    done
}

setup_proxy_env() {
    DOCKER_BRIDGE_IP=$(docker network inspect bridge --format='{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || echo "172.17.0.1")
    if [ -n "$http_proxy" ] || [ -n "$https_proxy" ]; then
        echo -e "${YELLOW}Detected Proxy. Config for Kind -> Host: $DOCKER_BRIDGE_IP${NC}"
        PROXY_PORT="7890" 
        if [[ "$http_proxy" =~ :([0-9]+)$ ]]; then PROXY_PORT=${BASH_REMATCH[1]}; fi
        export http_proxy="http://$DOCKER_BRIDGE_IP:$PROXY_PORT"
        export https_proxy="http://$DOCKER_BRIDGE_IP:$PROXY_PORT"
        export no_proxy="localhost,127.0.0.1,::1,$DOCKER_BRIDGE_IP,10.96.0.0/12,10.244.0.0/16,192.168.0.0/16,.svc,.cluster.local"
        export HTTP_PROXY="$http_proxy" HTTPS_PROXY="$https_proxy" NO_PROXY="$no_proxy"
    fi
}

setup_infrastructure() {
    echo -e "${GREEN}>>> [Phase 1] Infrastructure Setup${NC}"
    
    NEW_CLUSTER=false

    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        echo -e "${GREEN}Cluster '${CLUSTER_NAME}' exists. Skipping network setup.${NC}"
    else
        echo -e "${YELLOW}Creating Cluster '${CLUSTER_NAME}'...${NC}"
        NEW_CLUSTER=true
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
        HTTP_PROXY=$http_proxy HTTPS_PROXY=$https_proxy NO_PROXY=$no_proxy \
        kind create cluster --config /tmp/kind-config.yaml --name "$CLUSTER_NAME"
    fi

    if [ -f "$PROJECT_ROOT/Makefile" ]; then
        echo -e "${YELLOW}Building and Loading Agent Image...${NC}"
        (cd "$PROJECT_ROOT" && make images)
        kind load docker-image "$AGENT_IMAGE_NAME" --name "$CLUSTER_NAME"
        kind load docker-image "$CONTROLLER_IMAGE_NAME" --name "$CLUSTER_NAME"
    else
        echo -e "${RED}Warning: Makefile not found. Assuming image $AGENT_IMAGE_NAME and $CONTROLLER_IMAGE_NAME exists locally.${NC}"
        kind load docker-image "$AGENT_IMAGE_NAME" --name "$CLUSTER_NAME"
        kind load docker-image "$CONTROLLER_IMAGE_NAME" --name "$CLUSTER_NAME"
    fi

    if [ "$NEW_CLUSTER" = true ]; then
        echo -e "${YELLOW}Initializing CNI and Network Config for new cluster...${NC}"
        
        # CNI Setup
        if [ ! -f "/tmp/${CNI_ARCHIVE}" ]; then curl -L -s "$CNI_URL" -o "/tmp/${CNI_ARCHIVE}"; fi
        NODES=$(kind get nodes --name "$CLUSTER_NAME")
        for node in $NODES; do
            docker cp "/tmp/${CNI_ARCHIVE}" "$node:/root/${CNI_ARCHIVE}"
            docker exec "$node" bash -c "mkdir -p /opt/cni/bin && tar -C /opt/cni/bin -xzf /root/${CNI_ARCHIVE} && rm /root/${CNI_ARCHIVE}"
            docker exec --privileged "$node" modprobe br_netfilter || true
            docker exec --privileged "$node" sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null
            docker exec --privileged "$node" sysctl -w net.ipv4.ip_forward=1 >/dev/null
        done

        # Flannel Setup
        echo -e "${YELLOW}Installing Flannel (Host-GW mode)...${NC}"
        curl -sL "$FLANNEL_URL" | \
        sed 's/"Type": "vxlan"/"Type": "host-gw"/' | \
        sed '/- --kube-subnet-mgr/a \        - --iface=eth0' | \
        kubectl apply -f -
        
        kubectl rollout status daemonset/kube-flannel-ds -n kube-flannel --timeout=180s
    fi
}

deploy_agent_external() {
    echo -e "${GREEN}>>> [Phase 2] Deploying Agent from ${AGENT_YAML_PATH}${NC}"
    kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null

    echo "Creating Namespaces..."
    kubectl create ns kuro-experiment --dry-run=client -o yaml | kubectl apply -f -
    kubectl create ns kuro-system --dry-run=client -o yaml | kubectl apply -f -

    if [ ! -f "$AGENT_YAML_PATH" ]; then
        echo -e "${RED}Error: Agent configuration file not found at: $AGENT_YAML_PATH${NC}"
        echo -e "${RED}Please save your agent.yaml content to that path.${NC}"
        exit 1
    fi

    kubectl apply -f "$AGENT_YAML_PATH"
    kubectl apply -f "$CONTROLLER_YAML_PATH"

    echo "Restarting Agent DaemonSet to pick up changes..."
    kubectl rollout restart daemonset/kuro-agent -n kuro-system

    kubectl rollout restart deployment kuro-controller -n kuro-system

    echo "Waiting for Agents to be ready..."
    kubectl rollout status daemonset/kuro-agent -n kuro-system --timeout=60s
}

# ================= Execution =================

parse_args "$@"
setup_infrastructure
deploy_agent_external

echo -e "\n${GREEN}>>> All Systems Go! Cluster is running in Host-GW mode with External Agent Config.${NC}"
