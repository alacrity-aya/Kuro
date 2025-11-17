<div align="center">
    <h2>kuro: the project is still in progress...</h2>
</div>

---

## TODO:

1. adding cgroup eth port module
2. making the volume of token bucket configurable
3. how to move socket in cgroup ?
4. using std::source_location to upgrade logger


### flow limitation for pid

- Cgroup-skb: 这种方案的前提是把二进制程序挂在到systemd中，直接屏蔽了pid。通过对cgroup的控制进行限制流量，但问题是无法实时的控制流量
- tc: tc 层的 PID 不等于应用程序 PID，直接否决
- sockmap: 只适用于tcp

---

<div align="center">          
    <img src="assert/kuro.png" alt="kuro CG" width="70%">
</div>
