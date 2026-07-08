# GoMonTraff — High-Performance eBPF traffic usage exporter wrriten in Go + C
A production-grade, standalone network traffic exporter written in **Go** and **eBPF (C)** using `cilium/ebpf` and CO-RE (Compile Once – Run Everywhere).
This tool attaches eBPF classifier programs to both the ingress and egress traffic streams of a specific network interface via Traffic Control (`clsact` qdisc). It efficiently aggregates packet sizes matching a dynamic routing LPM (Longest Prefix Match) Trie map in kernel-space, and exposes these data deltas natively to a Prometheus scraping endpoint using 100% atomic batch map operations.
You can use tools like Prometheus, InfluxDB, or even ClickHouse (with a broker like Vector) to aggregate and SUM these metrics values ​​and bill your users, or use this as a simple monitoring tool

---

## Features

- **Architectural Excellence:** Built entirely using pure Go (`cilium/ebpf`) and standard BTF-annotated C code. **No runtime dependencies** on BCC, LLVM/Clang, or host kernel headers.
- **True CO-RE (Compile Once - Run Everywhere):** Uses `vmlinux.h` to read kernel data structures safely across different Linux kernel versions without recompilation.
- **Atomic Batch Map Operations:** Employs eBPF kernel batching APIs to look up and clear metrics atomically in a single operation, eliminating the data race and latency overhead of single-item map lookups.
- **Zero Leak Cleanup:** Listens for termination signals (`SIGINT`, `SIGTERM`) to cleanly remove the attached Traffic Control (`clsact`) filters from the host interface before exiting.
- **Docker Ready:** Ready to build and run inside a Docker container
---
## Architecture Diagram
```text
               +-------------------------------------------------+
               |                   KERNEL SPACE                  |
               |                                                 |
  [Ingress] ---> [TC clsact filter]                              |
               |         |                                       |
  [Egress]  ---> [TC clsact filter]                              |
               |         |                                       |
               |         v                                       |
               |   Is IP within       NO                         |
               |  Monitored Subnet? ------> (Allow Packet/Ignore)|
               |         |                                       |
               |         | YES                                   |
               |         v                                       |
               |  Atomic Add to BPF Map                          |
               |  (traffic_map Hash Map)                         |
               |                                                 |
               +-----------------|-------------------------------+
                                 |
                     Batch Read  | Atomic Lookup
                     and Delete  | & Clear Loop
                                 v
               +-----------------|-------------------------------+
               |                   USER SPACE                    |
               |                                                 |
               |        [traffic-exporter Go Daemon]             |
               |                     |                           |
               |                     v                           |
               |          Exposes Prometheus Metrics             |
               |             (Default: :8000/metrics)            |
               +-------------------------------------------------+
```
---
## Prerequisites

Before building or running the project, ensure your host environment satisfies the following requirements:

- **Operating System:** Linux Kernel version `5.8` or newer (required for eBPF HASH/LPM Trie batch operations and stable `clsact` attachments).
- **Go Toolchain:** Go `1.21` or later installed.
- **System Utilities:** `bpftool` must be installed on the system to extract the kernel's BTF data layer during compilation.
  - *Ubuntu/Debian:*
  ```bash
  sudo apt install linux-tools-common \
  linux-tools-$(uname -r) \
  linux-headers-$(uname -r) \
  build-essential \
  libelf-dev \
  libbpf-dev
  ```

---

## Compilation & Build Instructions

1. **Initialize the Project Workspace:**

```bash
git clone https://github.com/MortyTech/gomontraff.git
cd gomontraff/
go mod init gomontraff
go mod tidy
make
```

---

## Environment Variables Configuration

The application is controlled entirely via environment variables. Configure them inline or through your orchestration environment:

| Environment Variable | Default Value | Description |
| --- | --- | --- |
| `MONITOR_INTERFACE` | `eno1` | The name of the host network interface to attach eBPF filters to (e.g., `eth0`, `bond0`). |
| `MONITOR_SUBNETS` | `172.16.0.0/16,192.168.1.0/24` | Comma-separated list of IPv4 subnets to monitor. Traffic outside these subnets is ignored. |
| `REFRESH_INTERVAL` | `60` | The window interval (in seconds) at which the user-space daemon clears the eBPF map and updates Prometheus. |
| `EXPORTER_BIND_ADDR` | `0.0.0.0` | The host network IP address the Prometheus metric server should bind to. |
| `EXPORTER_PORT` | `8000` | The TCP port the Prometheus metrics engine will listen on. |

---

## How to Run Standalone Mode

After succsussful build you can run stanalone binary
Because this tool interacts with kernel-level packet classifiers, **it must be run with root or `CAP_BPF` / `CAP_NET_ADMIN` privileges**:

```bash
sudo MONITOR_INTERFACE="eth0" \
     MONITOR_SUBNETS="10.0.0.0/8,172.16.0.0/12" \
     REFRESH_INTERVAL="10" \
     ./gomontraff
```
## Prometheus Exposition Metric Sample Output

Once running, the metrics server will expose the data delta calculated exactly within that current `REFRESH_INTERVAL` window. Stale metrics are wiped cleanly at the start of each window, forcing inactive IPs to drop out instead of presenting frozen counts.

Querying the endpoint via `curl http://127.0.0.1:8000/metrics` yields formatted outputs matching this behavior:

```text
# HELP traffic_bytes Network traffic delta in bytes within the last refresh window
# TYPE traffic_bytes gauge
traffic_bytes{direction="rx",interface="eth0",ip="10.0.0.15"} 410294
traffic_bytes{direction="tx",interface="eth0",ip="10.0.0.15"} 88412
traffic_bytes{direction="rx",interface="eth0",ip="172.16.4.92"} 1054
traffic_bytes{direction="tx",interface="eth0",ip="172.16.4.92"} 0
traffic_bytes{direction="rx",interface="eth0",ip="10.150.22.101"} 12495003
traffic_bytes{direction="tx",interface="eth0",ip="10.150.22.101"} 4210955
```
## Run by Docker-Compose Mode

```bash
git clone https://github.com/MortyTech/gomontraff.git
cd gomontraff/
docker compose up -d
```

## Docker run

```bash
git clone https://github.com/MortyTech/gomontraff.git
cd gomontraff/
docker build -t gomontraff .
docker run -d \
  --name gomontraff \
  --net=host \
  --privileged \
  -e MONITOR_INTERFACE="bond0" \
  -e MONITOR_SUBNETS="172.16.0.0/16,192.168.1.0/24" \
  -e REFRESH_INTERVAL="30" \
  -e EXPORTER_BIND_ADDR="0.0.0.0" \
  -e EXPORTER_PORT="8000" \
  --restart unless-stopped \
  gomontraff:latest
```
