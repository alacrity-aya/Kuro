#!/bin/bash
set -e

CLUSTER_NAME="kuro-dev"
IMAGE_NAME="kuro-agent:dev"

if kind get clusters | grep -q "$CLUSTER_NAME"; then
    echo "Cluster '$CLUSTER_NAME' already exists."
else
    kind create cluster --config deploy/kind-config.yaml --name "$CLUSTER_NAME"
    
    cilium install \
    --set kubeProxyReplacement=true \
    --wait
    
    cilium status --wait
    
    kubectl create ns kuro-experiment --dry-run=client -o yaml | kubectl apply -f -
    kubectl create ns kuro-system --dry-run=client -o yaml | kubectl apply -f -
fi

echo "Running make images..."
make images

echo "Loading $IMAGE_NAME into Kind..."
kind load docker-image $IMAGE_NAME --name "$CLUSTER_NAME"

echo "Deploying Agent..."
kubectl apply -f deploy/agent.yaml

echo "Waiting for Rollout..."
kubectl rollout status daemonset/kuro-agent -n kuro-system --timeout=60s

echo "Environment Ready!"
