kind load docker-image kuro-agent:dev
kind load docker-image kuro-controller:dev

kubectl delete -f test-env.yaml
kubectl delete -f agent.yaml
kubectl delete -f controller.yaml

kubectl apply -f namespace.yaml
kubectl apply -f test-env.yaml
kubectl apply -f agent.yaml
kubectl apply -f controller.yaml

kubectl get pods -n kuro-system      
kubectl get pods -n kuro-experiment  
