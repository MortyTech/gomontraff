# GoMonTraff — Go + cilium/ebpf traffic billing exporter

A high-performance, low-overhead network traffic monitoring agent written in **Go** and **eBPF (C with CO-RE)**. This project replaces a legacy Python + BCC implementation with a single, statically linked, production-grade Go binary. 

It instruments network interfaces at the Traffic Control (TC) layer via a `clsact` qdisc, matches IPv4 traffic against a high-performance LPM (Longest Prefix Match) Trie map containing monitored subnets, and natively aggregates packet counts in a kernel-space hash map. A userspace loop reads and clears metrics atomically via eBPF batch map operations, exporting them to a Prometheus `/metrics` endpoint.

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
