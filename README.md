<div align="center">
    <h2>kuro: the project is still in progress...</h2>
</div>

<div align="center">          
    <img src="assert/kuro.png" alt="kuro CG" width="70%">
</div>

## todo

- agent
    - agent restart
    - pin bpf map
    - incorrect loss 
    - fq limit
    - jitter
    - ```yaml
        selector:
        mode: "manual"
        protocol: "UDP"
        dest_port: 8080
        ```

- upstream(nelink bug)
    - create PR for this [issue](https://github.com/vishvananda/netlink/issues/480) 

- self-healing

- Use topology-aware to distinguish between business traffic and simulated traffic.
- the key of bpf map should be dst ip
