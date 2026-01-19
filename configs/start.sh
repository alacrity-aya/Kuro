kind load docker-image kuro-agent:dev
kubectl create namespace kuro-experiment
kubectl apply -f kuro-crd.yaml
kubectl apply -f kuro-workload.yaml
