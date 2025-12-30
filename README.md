<div align="center">
    <h2>kuro: the project is still in progress...</h2>
</div>

<div align="center">          
    <img src="assert/kuro.png" alt="kuro CG" width="70%">
</div>

## todo

- important
    - vxlan across host
    - CNI

- bugs
    - 'ctrl + c' not works for server
    - timestamp uint64/int64

- bpf
    - combine treffic_rule and netem rule to improve performance
    - sync time
    - mark flow passing by vxlan(traffic limit)

- control
    - don't crash when client panic
    - validate config file(like ip)

- config
    - client target should be configurable
    - check node.ip is valid or have contradiction
    - vxlan should be update


- rpc
    - use enum or something to describe client capabilities 
    - dynamic rule

- victoria metrics
    - upload config

- control panel
    - RPC(across hosts)
    - UDS(local only)

- across hosts
    - add ip addr to vxlan
    - add default route(vxlan)

- config file
    - python sdk to write config file
    - gui(Tauri: Typescript + rust)


- sandbox
    - node - cgroup - netns

- upstream(nelink bug)
    - create PR for this [issue](https://github.com/vishvananda/netlink/issues/480) 

