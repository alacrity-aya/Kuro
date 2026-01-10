kind load docker-image kuro-agent:dev
kind load docker-image kuro-controller:dev

kubectl apply -f test-env.yaml
kubectl apply -f agent.yaml
kubectl apply -f controller.yaml


