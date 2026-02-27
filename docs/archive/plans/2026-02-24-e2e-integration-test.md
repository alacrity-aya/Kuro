# E2E Integration Test Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Verify frontend features work correctly with real K8s backend, including topology creation, traffic control, and Grafana metrics visualization.

**Architecture:** 
- Frontend (React + Vite) → API Server (port 8080) → Controller → K8s CRDs → Agent (eBPF)
- Prometheus scrapes Agent metrics → Grafana displays dashboards

**Tech Stack:** React 18, TypeScript, Go, Kubernetes (Kind), eBPF, Prometheus, Grafana

**Prerequisites:**
- Kind cluster running with controller and agents deployed
- Frontend built and running with `VITE_USE_MOCK_API=false`
- Prometheus and Grafana deployed in kuro-monitor namespace
- Port-forwards established: API (8080), Grafana (30092), Prometheus (30091)

---

## Phase 1: Environment Setup and Verification

### Task 1.1: Verify K8s Cluster Status

**Step 1: Check cluster is running**

Run:
```bash
kubectl get nodes
kubectl get pods -n kuro-system
kubectl get pods -n kuro-monitor
```

Expected:
- 3 nodes (1 control-plane, 2 workers)
- kuro-controller and kuro-agent pods Running
- prometheus and grafana pods Running

**Step 2: Verify port-forwards**

Run:
```bash
# Kill existing port-forwards
pkill -f "port-forward.*kuro-controller" 2>/dev/null || true
pkill -f "port-forward.*grafana" 2>/dev/null || true
pkill -f "port-forward.*prometheus" 2>/dev/null || true

# Start port-forwards
kubectl port-forward svc/kuro-controller -n kuro-system 8080:8080 &
kubectl port-forward svc/grafana -n kuro-monitor 30092:3000 &
kubectl port-forward svc/prometheus -n kuro-monitor 30091:9090 &

sleep 3

# Verify
curl -s http://localhost:8080/api/v1/namespaces/kuro-experiment/networktopologies | jq '.items | length'
curl -s http://localhost:30092/api/health
curl -s http://localhost:30091/-/healthy
```

Expected: All endpoints respond successfully

---

### Task 1.2: Start Frontend with Real API

**Step 1: Configure environment**

Run:
```bash
cat > /home/alacrity/work/vibe/Kuro/frontend/.env.local << 'EOF'
# Use real backend API
VITE_USE_MOCK_API=false

# Kuro API base URL (proxied through vite to port 8080)
VITE_API_BASE_URL=/api/v1

# Prometheus URL for metrics
VITE_PROMETHEUS_URL=http://localhost:30091

# Use real Prometheus
VITE_USE_MOCK_PROMETHEUS=false

# Grafana URL
VITE_GRAFANA_URL=http://localhost:30092
EOF
```

**Step 2: Start frontend**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro/frontend && npm run dev &
sleep 5
curl -s http://localhost:5173 | head -5
```

Expected: Frontend running on port 5173 (or 5174 if 5173 occupied)

---

## Phase 2: Topology Creation Tests (Commits dc26685, 1bbd9c2, 653bd11)

### Task 2.1: Test Visual Mode Topology Creation

**Files:**
- Frontend page: `http://localhost:5174/topologies/create`
- K8s verification: `kubectl get networktopology,pods -n kuro-experiment`

**Step 1: Navigate to create page**

Using browser automation (Playwright):
```javascript
await page.goto('http://localhost:5174/topologies/create');
await page.waitForSelector('.visual-editor');
```

**Step 2: Verify Visual Editor displays default groups**

Expected:
- VisualEditor shows 2 nodes: "leader" and "follower"
- ConfigPanel shows Basic Info section with Name and Namespace fields
- Default namespace: "kuro-experiment"

**Step 3: Fill topology name**

```javascript
await page.getByRole('textbox', { name: 'Name' }).fill('e2e-test-topology');
```

**Step 4: Click leader node to select**

```javascript
await page.getByText('leader').first().click();
```

Expected: Edit Group panel shows leader details

**Step 5: Modify leader replicas to 2**

```javascript
await page.getByRole('spinbutton').fill('2');
```

**Step 6: Add new node group**

```javascript
await page.getByRole('button', { name: '+ Add' }).click();
```

Expected: New group "group-3" appears

**Step 7: Submit topology**

```javascript
await page.getByRole('button', { name: 'Create Topology' }).click();
await page.waitForURL(/\/topologies\/kuro-experiment\/e2e-test-topology/);
```

**Step 8: Verify in K8s**

Run:
```bash
kubectl get networktopology e2e-test-topology -n kuro-experiment -o yaml
kubectl get pods -n kuro-experiment -l kuro.io/topology=e2e-test-topology
```

Expected:
- NetworkTopology CR exists with 3 node groups
- Pods created with correct labels

---

### Task 2.2: Test YAML Mode Topology Creation

**Step 1: Navigate to create page and switch to YAML mode**

```javascript
await page.goto('http://localhost:5174/topologies/create');
await page.getByRole('button', { name: 'YAML' }).click();
```

**Step 2: Verify YAML editor appears**

Expected: Monaco editor displays with YAML content

**Step 3: Edit YAML directly**

```yaml
apiVersion: simulation.kuro.io/v1alpha1
kind: NetworkTopology
metadata:
  name: yaml-test-topology
  namespace: kuro-experiment
spec:
  nodeGroups:
    - name: server
      replicas: 1
      image: nicolaka/netshoot:latest
      labels:
        role: server
    - name: client
      replicas: 2
      image: nicolaka/netshoot:latest
      labels:
        role: client
```

**Step 4: Submit topology**

```javascript
await page.getByRole('button', { name: 'Create Topology' }).click();
```

**Step 5: Verify in K8s**

Run:
```bash
kubectl get networktopology yaml-test-topology -n kuro-experiment
kubectl wait --for=condition=available deployment -l kuro.io/topology=yaml-test-topology -n kuro-experiment --timeout=60s
```

**Step 6: Verify pods have network tools**

Run:
```bash
kubectl exec -n kuro-experiment deployment/yaml-test-topology-server -- which iperf3
kubectl exec -n kuro-experiment deployment/yaml-test-topology-server -- which ping
```

Expected: iperf3 and ping available in pods

---

### Task 2.3: Test Visual/YAML Mode Toggle Synchronization

**Step 1: Create topology in Visual mode**

```javascript
await page.goto('http://localhost:5174/topologies/create');
await page.getByRole('textbox', { name: 'Name' }).fill('sync-test-topology');
```

**Step 2: Switch to YAML mode and verify content**

```javascript
await page.getByRole('button', { name: 'YAML' }).click();
const yamlContent = await page.locator('.monaco-editor').textContent();
```

Expected: YAML contains correct topology name and node groups

**Step 3: Edit YAML and switch back**

Edit YAML to change replicas, then:
```javascript
await page.getByRole('button', { name: 'Visual' }).click();
```

Expected: Visual editor reflects YAML changes

---

## Phase 3: Traffic Control Tests (Commits 65146c1, ebe8ac9, 446d036)

### Task 3.1: Test Traffic Controls Menu Navigation

**Step 1: Click Traffic Controls menu**

```javascript
await page.goto('http://localhost:5174');
await page.getByRole('button', { name: 'Traffic Controls' }).click();
await page.waitForURL(/\/traffic-controls/);
```

Expected: TrafficControlList page loads

---

### Task 3.2: Test TrafficControl List Page

**Step 1: Verify list page displays**

Expected:
- Header shows "Traffic Controls"
- Create button exists
- List shows existing traffic controls (may be empty)

**Step 2: Create TrafficControl via frontend**

```javascript
await page.getByRole('button', { name: 'Create Traffic Control' }).click();
await page.waitForURL(/\/traffic-controls\/create/);
```

---

### Task 3.3: Test TrafficControl Creation with Real Traffic

**Prerequisites:** Topology with pods that have iperf3 (yaml-test-topology from Task 2.2)

**Step 1: Navigate to create page**

```javascript
await page.goto('http://localhost:5174/traffic-controls/create');
```

**Step 2: Fill TrafficControl form**

```javascript
await page.getByRole('textbox', { name: 'Name' }).fill('e2e-bandwidth-limit');
await page.getByRole('combobox').first().selectOption('yaml-test-topology'); // Topology
await page.getByRole('combobox').nth(1).selectOption('client'); // Source
await page.getByRole('combobox').nth(2).selectOption('server'); // Destination
await page.getByRole('textbox', { name: 'Bandwidth' }).fill('10Mbps');
await page.getByRole('textbox', { name: 'Latency' }).fill('20ms');
await page.getByRole('textbox', { name: 'Jitter' }).fill('5ms');
await page.getByRole('textbox', { name: 'Packet Loss' }).fill('0.5');
await page.getByRole('button', { name: 'Create Traffic Control' }).click();
```

**Step 3: Verify TrafficControl in K8s**

Run:
```bash
kubectl get trafficcontrol e2e-bandwidth-limit -n kuro-experiment -o yaml
```

Expected: TrafficControl CR exists with correct spec

**Step 4: Get pod IPs for traffic test**

Run:
```bash
SERVER_IP=$(kubectl get pod -n kuro-experiment -l role=server -o jsonpath='{.items[0].status.podIP}')
CLIENT_POD=$(kubectl get pod -n kuro-experiment -l role=client -o jsonpath='{.items[0].metadata.name}')
echo "Server IP: $SERVER_IP"
echo "Client Pod: $CLIENT_POD"
```

**Step 5: Start iperf3 server**

Run:
```bash
kubectl exec -n kuro-experiment deployment/yaml-test-topology-server -- iperf3 -s -D
```

**Step 6: Run iperf3 client and measure bandwidth**

Run:
```bash
kubectl exec -n kuro-experiment $CLIENT_POD -- iperf3 -c $SERVER_IP -t 10 -J | jq '.end.sum_received.bits_per_second'
```

Expected: Bandwidth close to 10Mbps (within tolerance)

**Step 7: Test ping latency**

Run:
```bash
kubectl exec -n kuro-experiment $CLIENT_POD -- ping -c 10 $SERVER_IP | tail -1
```

Expected: Average latency around 20ms (plus baseline)

---

### Task 3.4: Test TrafficControl Delete

**Step 1: Delete TrafficControl from list**

```javascript
await page.goto('http://localhost:5174/traffic-controls');
await page.getByRole('button', { name: 'Delete' }).first().click();
// Handle confirmation dialog
page.on('dialog', dialog => dialog.accept());
```

**Step 2: Verify deletion in K8s**

Run:
```bash
kubectl get trafficcontrol e2e-bandwidth-limit -n kuro-experiment
```

Expected: TrafficControl not found

---

## Phase 4: Grafana Integration Tests (Commits 5512772, 606bbe2)

### Task 4.1: Test Grafana Dashboard Accessibility

**Step 1: Open Grafana in new tab**

```javascript
const [grafanaPage] = await Promise.all([
  context.waitForEvent('page'),
  page.getByRole('link', { name: 'Open Grafana' }).click()
]);
await grafanaPage.waitForLoadState();
```

**Step 2: Verify Kuro Dashboard exists**

Run:
```bash
curl -s "http://localhost:30092/api/search?query=kuro" | jq '.[] | select(.title | contains("Kuro"))'
```

Expected: Dashboard "Kuro Network Metrics" found

---

### Task 4.2: Generate Traffic and Verify Metrics

**Step 1: Start continuous traffic**

Run in background:
```bash
# Get pod info
SERVER_IP=$(kubectl get pod -n kuro-experiment -l role=server -o jsonpath='{.items[0].status.podIP}')
CLIENT_POD=$(kubectl get pod -n kuro-experiment -l role=client -o jsonpath='{.items[0].metadata.name}')

# Start server
kubectl exec -n kuro-experiment deployment/yaml-test-topology-server -- iperf3 -s -D

# Run continuous traffic for 30 seconds
kubectl exec -n kuro-experiment $CLIENT_POD -- iperf3 -c $SERVER_IP -t 30 &
```

**Step 2: Wait for metrics collection**

Run:
```bash
sleep 35
```

**Step 3: Query Prometheus for metrics**

Run:
```bash
# Query bandwidth metrics
curl -s 'http://localhost:30091/api/v1/query?query=rate(kuro_pod_traffic_bytes_total%7Btype%3D%22sim%22%7D%5B1m%5D)' | jq '.data.result | length'

# Query active pods
curl -s 'http://localhost:30091/api/v1/query?query=count(kuro_pod_traffic_bytes_total)' | jq '.data.result[0].value[1]'
```

Expected: 
- Bandwidth query returns results
- Active pods count matches running pods

**Step 4: Verify Grafana dashboard shows data**

Navigate to Grafana dashboard and verify:
- Bandwidth panel shows traffic graph
- Active Pods shows correct count

---

### Task 4.3: Test MetricsPage Grafana Link

**Step 1: Navigate to Metrics page**

```javascript
await page.goto('http://localhost:5174/metrics');
```

**Step 2: Verify Open Grafana button exists**

Expected: Button with text "Open Grafana" or similar

**Step 3: Click button and verify new tab opens**

```javascript
const [newPage] = await Promise.all([
  context.waitForEvent('page'),
  page.getByRole('link', { name: /grafana/i }).click()
]);
expect(newPage.url()).toContain('30092');
```

---

## Phase 5: Full E2E Scenario Test

### Task 5.1: Complete Workflow Test

**Scenario:** Create topology → Create traffic control → Generate traffic → Verify in Grafana

**Step 1: Create topology with traffic-generating pods**

Run:
```bash
kubectl apply -f - <<EOF
apiVersion: simulation.kuro.io/v1alpha1
kind: NetworkTopology
metadata:
  name: full-e2e-test
  namespace: kuro-experiment
spec:
  nodeGroups:
    - name: traffic-server
      replicas: 1
      image: nicolaka/netshoot:latest
      labels:
        role: traffic-server
    - name: traffic-client
      replicas: 2
      image: nicolaka/netshoot:latest
      labels:
        role: traffic-client
EOF

kubectl wait --for=condition=available deployment -l kuro.io/topology=full-e2e-test -n kuro-experiment --timeout=120s
```

**Step 2: Create TrafficControl via API**

Run:
```bash
curl -X POST http://localhost:8080/api/v1/namespaces/kuro-experiment/trafficcontrols \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "simulation.kuro.io/v1alpha1",
    "kind": "TrafficControl",
    "metadata": {
      "name": "full-e2e-tc",
      "namespace": "kuro-experiment"
    },
    "spec": {
      "source": {
        "matchLabels": {"role": "traffic-client"}
      },
      "destination": {
        "matchLabels": {"role": "traffic-server"}
      },
      "policy": {
        "bandwidth": "50Mbps",
        "latency": "10ms",
        "jitter": "2ms",
        "packetLoss": "0.1%"
      }
    }
  }'
```

**Step 3: Wait for TrafficControl to be applied**

Run:
```bash
sleep 5
kubectl get trafficcontrol full-e2e-tc -n kuro-experiment -o jsonpath='{.status.phase}'
```

**Step 4: Generate traffic**

Run:
```bash
SERVER_IP=$(kubectl get pod -n kuro-experiment -l role=traffic-server -o jsonpath='{.items[0].status.podIP}')
kubectl exec -n kuro-experiment deployment/full-e2e-test-traffic-server -- iperf3 -s -D

# Run multiple iperf tests
for i in {1..5}; do
  kubectl exec -n kuro-experiment -l role=traffic-client -- iperf3 -c $SERVER_IP -t 5 &
  sleep 6
done
```

**Step 5: Verify metrics in Prometheus**

Run:
```bash
curl -s 'http://localhost:30091/api/v1/query?query=rate(kuro_pod_traffic_bytes_total%5B1m%5D)' | jq '.data.result | map(.value[1]) | map(tonumber) | add'
```

Expected: Non-zero value indicating traffic was measured

**Step 6: Verify Grafana dashboard**

Open: http://localhost:30092

Expected:
- Bandwidth panel shows traffic spikes
- Active Pods shows 3 (1 server + 2 clients)

**Step 7: Verify bandwidth limit is enforced**

Run:
```bash
# Measure actual bandwidth
kubectl exec -n kuro-experiment -l role=traffic-client -- iperf3 -c $SERVER_IP -t 10 -J | jq '.end.sum_received.bits_per_second / 1000000'
```

Expected: Around 50 Mbps (within 30% tolerance)

---

## Phase 6: Cleanup and Final Verification

### Task 6.1: Cleanup Test Resources

Run:
```bash
# Delete test topologies
kubectl delete networktopology e2e-test-topology yaml-test-topology sync-test-topology full-e2e-test -n kuro-experiment 2>/dev/null || true

# Delete test traffic controls
kubectl delete trafficcontrol e2e-bandwidth-limit full-e2e-tc -n kuro-experiment 2>/dev/null || true

# Wait for pods to terminate
kubectl wait --for=delete pod -l kuro.io/topology -n kuro-experiment --timeout=60s 2>/dev/null || true
```

---

### Task 6.2: Final Status Report

**Step 1: Collect test results**

Create summary:
```bash
echo "=== E2E Test Summary ==="
echo ""
echo "K8s Cluster Status:"
kubectl get nodes -o wide
echo ""
echo "Controller Status:"
kubectl get pods -n kuro-system
echo ""
echo "Monitoring Stack Status:"
kubectl get pods -n kuro-monitor
echo ""
echo "Remaining Test Resources:"
kubectl get networktopology,trafficcontrol -n kuro-experiment
```

---

## Summary

| Phase | Tasks | What's Tested |
|-------|-------|---------------|
| Phase 1 | 2 | Environment setup, real API mode |
| Phase 2 | 3 | Topology Visual/YAML creation, toggle sync |
| Phase 3 | 4 | TrafficControl CRUD, bandwidth limit verification |
| Phase 4 | 3 | Grafana dashboard, metrics collection |
| Phase 5 | 1 | Full end-to-end workflow |
| Phase 6 | 2 | Cleanup and reporting |

**Total: 15 tasks**
