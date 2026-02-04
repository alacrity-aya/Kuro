kubectl port-forward svc/prometheus -n kuro-monitor 30091:9090 > /dev/null 2>&1 &
kubectl port-forward svc/grafana -n kuro-monitor 30092:3000 > /dev/null 2>&1 &
