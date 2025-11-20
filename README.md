<div align="center">
    <h2>kuro: the project is still in progress...</h2>
</div>


## TODO:

1. adding cgroup eth port module
2. making the volume of token bucket configurable
3. how to move socket in cgroup ?
4. using std::source_location to print better informatoin and using macro to improve performance
5. the management of services is too bad, refactor it with libsystemd !
6. use common.h to provide identical struct for cgroup.cpp and bpf.c

### flow limitation for pid

> I will use cgroup + systemd to solve this

---

<div align="center">          
    <img src="assert/kuro.png" alt="kuro CG" width="70%">
</div>
