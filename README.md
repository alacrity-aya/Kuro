<div align="center">
    <h2>kuro: the project is still in progress...</h2>
</div>

<div align="center">          
    <img src="assert/kuro.png" alt="kuro CG" width="70%">
</div>

## todo

- bugs
    - 'ctrl + c' not works for server
    - timestamp uint64/int64

- control
    - don't crash when client panic

- manager
    - the field manager in client should be an interface

- specs
    - update NetemSpec, the field limit is useless

- rpc
    - use enum or something to describe client capabilities 
    - complete service: ReportTraffic
    - offline state
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

