<div align="center">
    <h2>kuro: the project is still in progress...</h2>
</div>


## TODO:

1. adding cgroup eth port module
2. making the volume of token bucket configurable
3. how to move socket in cgroup ?
4. using std::source_location to upgrade logger
5. update error, for example:

```C++
struct DetailedError {
    ModuleError code;
    std::string message;
    int system_errno = 0; 

    std::string to_string() const {
        std::string base_msg = error_to_string(code);
        
        return base_msg + (message.empty() ? "" : ": " + message) + 
               (system_errno != 0 ? " (errno: " + std::to_string(system_errno) + ")" : "");
    }
};

using ModuleResult = std::expected<void, DetailedError>;

ModuleResult some_function() {
    if (/* failed */) {
        return std::unexpected { 
            DetailedError {
                ModuleError::OPEN_AND_LOAD_BPF_FAILED,
                "Could not open skel file at /path/to/bpf.o",
                errno 
            } 
        };
    }
    return {};
}

if (auto ret = some_function(); !ret.has_value()) {
    logger->error("Operation failed: {}", ret.error().to_string()); 
}
```


### flow limitation for pid

- Cgroup-skb: I will use cgroup + systemd to solve this

---

<div align="center">          
    <img src="assert/kuro.png" alt="kuro CG" width="70%">
</div>
