# Ideas

* stats module with `mpsc` channel to send blocking reason
* multiple thread with `SO_REUSEPORT` to have multiple process using the same port
```toml
[server]
# Allows multiple processes to bind to the same port for hardware-level scaling
reuse_port = true
# Number of internal async threads per worker process
worker_threads = 4 
# Optimization: Pin each worker to a specific CPU core (Core Affinity)
cpu_pinning = true
```
* IPv6 support
* when loading ABP rules, generate if specified the ABP rule file with only CSS/JS rules