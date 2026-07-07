# GoMonTraff — Go + cilium/ebpf traffic usage exporter

A high-performance, low-overhead network traffic monitoring agent written in **Go** and **eBPF (C with CO-RE)**.
This project replaces a legacy Python + BCC implementation with a single, statically linked, production-grade Go binary. 

It instruments network interfaces at the Traffic Control (TC) layer via a `clsact` qdisc, matches IPv4 traffic against a high-performance LPM (Longest Prefix Match) Trie map containing monitored subnets, and natively aggregates packet counts in a kernel-space hash map. A userspace loop reads and clears metrics atomically via eBPF batch map operations, exporting them to a Prometheus `/metrics` endpoint.

## Features

    Architectural Isolation: 100% written in Go + C. Completely removes execution runtime dependencies on Python, BCC (libbcc), LLVM, Clang, or host kernel headers.

    CO-RE (Compile Once – Run Everywhere): Uses vmlinux.h generated from BTF data. The binary compiles down to a single standalone artifact that executes across different kernel versions without on-the-fly recompilation.

    # Atomic Batch Map Operations:
    Replicates high-efficiency bulk map collection and eviction (BatchLookupAndDelete) in a single syscall context window, guaranteeing no packet tracking data is leaked or omitted between refresh intervals.

    Native Netlink Management: Avoids shell-out or Python dependencies for network interface tooling; configurations are bound and unregistered safely via direct netlink sockets.
---

## Architecture Flow

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
