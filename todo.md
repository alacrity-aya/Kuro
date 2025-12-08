
# host1

- node
  - metadata
    - node_name
    - container
    - image
    - exec
    - args
    - ip
  - rule
    - algo
    - rate
    - burst
  
- router
  - dst_cidr
  - out_node

- vxlan



# host2

- node
  - metadata
    - node_name
    - container
    - image
    - exec
    - args
    - ip
  - rule
    - algo
    - rate
    - burst
  
- router
  - dst_cidr
  - out_node

- vxlan
  - physical_iface = "eth0"

```toml
[[vxlan_redirect_rules]]
dst_ip_key = "10.0.0.11"
target_iface_name = "vxlan0"

[vxlan_redirect_rules.tunnel_metadata]
vni = 100
remote_vtep_ip = "192.168.1.51"
inner_dst_mac = "01:23:45:67:89:ab"
ttl = 64
```
