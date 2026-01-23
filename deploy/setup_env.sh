#!/bin/bash
set -e

CNI_TYPE="flannel"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --cilium) CNI_TYPE="cilium" ;;
        --kindnet) CNI_TYPE="kindnet" ;;
        --flannel) CNI_TYPE="flannel" ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

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
AGENT_YAML_PATH="$PROJECT_ROOT/deploy/agent.yaml"

CILIUM_VERSION="v1.18.5"
CILIUM_ENVOY_TAG="v1.34.12-1765374555-6a93b0bbba8d6dc75b651cbafeedb062b2997716"
CNI_PLUGINS_VERSION="v1.3.0" 

echo "----------------------------------------------------"
echo "Target CNI: $CNI_TYPE"
echo "----------------------------------------------------"

cat <<EOF > "$TEMP_CONFIG"
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
networking:
EOF

if [ "$CNI_TYPE" == "cilium" ]; then
    cat <<EOF >> "$TEMP_CONFIG"
  disableDefaultCNI: true
  kubeProxyMode: "none"
EOF
elif [ "$CNI_TYPE" == "flannel" ]; then
    cat <<EOF >> "$TEMP_CONFIG"
  disableDefaultCNI: true
  podSubnet: "10.244.0.0/16"
EOF
else
    cat <<EOF >> "$TEMP_CONFIG"
  disableDefaultCNI: false
EOF
fi

if kind get clusters | grep -q "$CLUSTER_NAME"; then
    echo "Cluster '$CLUSTER_NAME' already exists."
else
    echo "Creating cluster '$CLUSTER_NAME' with CNI: $CNI_TYPE..."
    HTTP_PROXY=http://172.18.0.1:7890 HTTPS_PROXY=http://172.18.0.1:7890 kind create cluster --config "$TEMP_CONFIG" --name "$CLUSTER_NAME"

    if [ "$CNI_TYPE" == "cilium" ]; then
        echo "----------------------------------------------------"
        echo "Manually pulling Cilium images inside Kind nodes..."
        
        KIND_NODES=$(kind get nodes --name "$CLUSTER_NAME")

        for node in $KIND_NODES; do
             docker exec "$node" ctr -n k8s.io images pull --platform linux/amd64 quay.io/cilium/cilium:${CILIUM_VERSION}
             docker exec "$node" ctr -n k8s.io images pull --platform linux/amd64 quay.io/cilium/operator-generic:${CILIUM_VERSION}
             docker exec "$node" ctr -n k8s.io images pull --platform linux/amd64 quay.io/cilium/cilium-envoy:${CILIUM_ENVOY_TAG}
        done

        echo "Installing Cilium ${CILIUM_VERSION}..."
        cilium install \
        --version "${CILIUM_VERSION}" \
        --set kubeProxyReplacement=true \
        --set image.pullPolicy=IfNotPresent \
        --set image.useDigest=false \
        --set operator.image.pullPolicy=IfNotPresent \
        --set operator.image.useDigest=false \
        --wait
        
        cilium status --wait

    elif [ "$CNI_TYPE" == "flannel" ]; then
        NODES=$(kind get nodes --name "$CLUSTER_NAME")
        
        echo "Downloading and installing standard CNI plugins for Flannel..."
        for node in $NODES; do
            echo "Processing node: $node"
            
            docker exec "$node" modprobe br_netfilter
            docker exec "$node" sh -c "echo '1' > /proc/sys/net/bridge/bridge-nf-call-iptables"
            
            echo "  > Installing CNI plugins ($CNI_PLUGINS_VERSION)..."
            docker exec "$node" bash -c "curl -L -s https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-amd64-${CNI_PLUGINS_VERSION}.tgz -o /tmp/cni-plugins.tgz"
            docker exec "$node" bash -c "mkdir -p /opt/cni/bin && tar -C /opt/cni/bin -xzf /tmp/cni-plugins.tgz"
            docker exec "$node" bash -c "rm /tmp/cni-plugins.tgz"
        done

        echo "Installing Flannel CNI..."
        kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
        
        echo "Waiting for Flannel to be ready..."
        kubectl rollout status daemonset/kube-flannel-ds -n kube-flannel --timeout=120s
        
    else
        echo "Using default Kind CNI (kindnet). No extra installation required."
    fi
fi

echo "Creating namespaces..."
kubectl create ns kuro-experiment --dry-run=client -o yaml | kubectl apply -f -
kubectl create ns kuro-system --dry-run=client -o yaml | kubectl apply -f -

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

echo "Environment Ready! (CNI: $CNI_TYPE)"
