#!/bin/bash
set -e

# ================= configuration =================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLUSTER_NAME="kuro-dev"
IMAGE_NAME="kuro-agent:dev"
AGENT_YAML_PATH="$PROJECT_ROOT/deploy/agent.yaml"
# Flannel Manifest
FLANNEL_MANIFEST="https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml"
CNI_PLUGINS_VERSION="v1.3.0" 
# ===========================================

DOCKER_BRIDGE_IP=$(docker network inspect bridge --format='{{(index .IPAM.Config 0).Gateway}}')
if [ -z "$DOCKER_BRIDGE_IP" ]; then
    echo "Error: Could not determine Docker Bridge IP."
    exit 1
fi

export http_proxy="http://$DOCKER_BRIDGE_IP:7890"
export https_proxy="http://$DOCKER_BRIDGE_IP:7890"
export all_proxy="socks5://$DOCKER_BRIDGE_IP:7890"
export no_proxy="localhost,127.0.0.1,$DOCKER_BRIDGE_IP,10.96.0.0/12,10.244.0.0/16,192.168.0.0/16,.svc,.cluster.local"

echo "----------------------------------------------------"
echo "Target CNI: Flannel (Robust Setup)"
echo "----------------------------------------------------"

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

if kind get clusters | grep -q "$CLUSTER_NAME"; then
    echo "Cluster '$CLUSTER_NAME' already exists. Deleting..."
    kind delete cluster --name "$CLUSTER_NAME"
fi

echo "Creating cluster '$CLUSTER_NAME'..."
HTTP_PROXY=http://172.18.0.1:7890 HTTPS_PROXY=http://172.18.0.1:7890 kind create cluster --config /tmp/kind-flannel.yaml --name "$CLUSTER_NAME"

echo "----------------------------------------------------"
echo "Fixing Nodes: Installing CNI plugins & Kernel Modules..."
echo "----------------------------------------------------"

NODES=$(kind get nodes --name "$CLUSTER_NAME")

for node in $NODES; do
    echo "Processing node: $node"
    
    docker exec "$node" bash -c "curl -L -s https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-amd64-${CNI_PLUGINS_VERSION}.tgz -o /tmp/cni-plugins.tgz"
    docker exec "$node" bash -c "mkdir -p /opt/cni/bin && tar -C /opt/cni/bin -xzf /tmp/cni-plugins.tgz"
    docker exec "$node" bash -c "rm /tmp/cni-plugins.tgz"
    
    echo "  > Loading br_netfilter kernel module..."
    docker exec --privileged "$node" modprobe br_netfilter || echo "Warning: modprobe failed, checking if built-in"
    docker exec --privileged "$node" modprobe nf_conntrack || true
    
    echo "  > Setting sysctl net.bridge.bridge-nf-call-iptables..."
    docker exec --privileged "$node" sysctl -w net.bridge.bridge-nf-call-iptables=1 || echo "Warning: could not set sysctl"
    
    docker exec "$node" mkdir -p /run/flannel
done

echo "----------------------------------------------------"
echo "Installing Flannel CNI..."
echo "----------------------------------------------------"

kubectl apply -f "$FLANNEL_MANIFEST"

echo "Waiting for Flannel to be ready..."
kubectl rollout status daemonset/kube-flannel-ds -n kube-flannel --timeout=180s

echo "----------------------------------------------------"
echo "Setting up Kuro Namespaces & Agent..."
echo "----------------------------------------------------"

kubectl create ns kuro-experiment --dry-run=client -o yaml | kubectl apply -f -
kubectl create ns kuro-system --dry-run=client -o yaml | kubectl apply -f -

echo "Running make images in $PROJECT_ROOT..."
if [ -f "$PROJECT_ROOT/Makefile" ]; then
    pushd "$PROJECT_ROOT" > /dev/null
    make images
    popd > /dev/null
else
    echo "Warning: Makefile not found, skipping image build."
fi

echo "Loading workspace image ($IMAGE_NAME) into Kind..."
kind load docker-image $IMAGE_NAME --name "$CLUSTER_NAME"

echo "Deploying Agent..."
if [ -f "$AGENT_YAML_PATH" ]; then
    kubectl apply -f "$AGENT_YAML_PATH"
    echo "Waiting for Rollout..."
    kubectl rollout status daemonset/kuro-agent -n kuro-system --timeout=60s
else
    echo "Error: Agent manifest not found at $AGENT_YAML_PATH"
fi

echo "Environment Ready!"
