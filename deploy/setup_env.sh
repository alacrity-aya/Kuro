#!/bin/bash
set -e

USE_CILIUM=false
if [[ "$1" == "--cilium" ]]; then
    USE_CILIUM=true
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEMP_CONFIG="/tmp/kind-config-generated.yaml"

DOCKER_BRIDGE_IP=$(docker network inspect bridge --format='{{(index .IPAM.Config 0).Gateway}}')

if [ -z "$DOCKER_BRIDGE_IP" ]; then
    echo "Error: Could not determine Docker Bridge IP."
    exit 1
fi

export http_proxy="http://$DOCKER_BRIDGE_IP:7890"
export https_proxy="http://$DOCKER_BRIDGE_IP:7890"
export all_proxy="socks5://$DOCKER_BRIDGE_IP:7890"
export no_proxy="localhost,127.0.0.1,$DOCKER_BRIDGE_IP,10.96.0.0/12,10.244.0.0/16,192.168.0.0/16,.svc,.cluster.local"

CLUSTER_NAME="kuro-dev"
IMAGE_NAME="kuro-agent:dev"
CILIUM_VERSION="v1.18.6"
AGENT_YAML_PATH="$PROJECT_ROOT/deploy/agent.yaml"

if $USE_CILIUM; then
cat <<EOF > "$TEMP_CONFIG"
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
networking:
  disableDefaultCNI: true
  kubeProxyMode: "none"
EOF
else
cat <<EOF > "$TEMP_CONFIG"
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
EOF
fi

if kind get clusters | grep -q "$CLUSTER_NAME"; then
    echo "Cluster '$CLUSTER_NAME' already exists."
else
    echo "Creating cluster '$CLUSTER_NAME' (Cilium: $USE_CILIUM)..."
    HTTP_PROXY=http://172.18.0.1:7890 HTTPS_PROXY=http://172.18.0.1:7890 kind create cluster --config "$TEMP_CONFIG" --name "$CLUSTER_NAME"

    if $USE_CILIUM; then
        echo "Installing Cilium ${CILIUM_VERSION}..."
        cilium install \
        --version "${CILIUM_VERSION}" \
        --set kubeProxyReplacement=true \
        --wait

        cilium status --wait
        
        kubectl create ns kuro-experiment --dry-run=client -o yaml | kubectl apply -f -
        kubectl create ns kuro-system --dry-run=client -o yaml | kubectl apply -f -
    else
        echo "Using default Kind CNI (kindnet)."
        kubectl create ns kuro-experiment --dry-run=client -o yaml | kubectl apply -f -
        kubectl create ns kuro-system --dry-run=client -o yaml | kubectl apply -f -
    fi
fi

echo "Running make images in $PROJECT_ROOT..."
pushd "$PROJECT_ROOT" > /dev/null
make images
popd > /dev/null

echo "Loading workspace image ($IMAGE_NAME) into Kind..."
kind load docker-image $IMAGE_NAME --name "$CLUSTER_NAME"

echo "Deploying Agent using manifest: $AGENT_YAML_PATH..."
kubectl apply -f "$AGENT_YAML_PATH"

echo "Waiting for Rollout..."
kubectl rollout status daemonset/kuro-agent -n kuro-system --timeout=60s

echo "Environment Ready!"
