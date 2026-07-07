package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type stats -type lpm_key_v4 bpf counter.bpf.c

const Version = "1.0.1"

var (
	iface            = getEnv("MONITOR_INTERFACE", "bond0")
	monitorSubnets   = getEnv("MONITOR_SUBNETS", "172.16.0.0/16,192.168.1.0/24")
	refreshInterval  = getEnvInt("REFRESH_INTERVAL", 30)
	exporterBindAddr = getEnv("EXPORTER_BIND_ADDR", "0.0.0.0")
	exporterPort     = getEnv("EXPORTER_PORT", "8000")
)

var trafficMetric = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "traffic_bytes",
		Help: "Network traffic delta in bytes within the last refresh window",
	},
	[]string{"ip", "direction", "interface"},
)

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if val, err := strconv.Atoi(value); err == nil {
			return val
		}
	}
	return fallback
}

// Safely determines host byte ordering without type compiler errors
func isLittleEndian() bool {
	var i uint16 = 0x1
	return *(*byte)(unsafe.Pointer(&i)) == 1
}

func main() {
	// --- 1. CLI Flags & Help Block ---
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of traffic-exporter:\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -h, --help      Show this help message and exit\n")
		fmt.Fprintf(os.Stderr, "  -v, --version   Show version information and exit\n\n")
		fmt.Fprintf(os.Stderr, "Environment Variables:\n")
		fmt.Fprintf(os.Stderr, "  MONITOR_INTERFACE   Target network interface to hook (default: \"bond0\")\n")
		fmt.Fprintf(os.Stderr, "  MONITOR_SUBNETS     Comma-separated IPv4 subnets to track (default: \"172.16.0.0/16,192.168.1.0/24\")\n")
		fmt.Fprintf(os.Stderr, "  REFRESH_INTERVAL    Window interval in seconds to poll & flush maps (default: 30)\n")
		fmt.Fprintf(os.Stderr, "  EXPORTER_BIND_ADDR  Prometheus HTTP listener binding address (default: \"0.0.0.0\")\n")
		fmt.Fprintf(os.Stderr, "  EXPORTER_PORT       Prometheus HTTP listener port (default: \"8000\")\n")
	}

	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&showVersion, "v", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("traffic-exporter version %s\n", Version)
		os.Exit(0)
	}

	// --- 2. EARLY NETWORK SOCKET VALIDATION (Failsafe) ---
	// Create the TCP server bind target string
	bindAddr := fmt.Sprintf("%s:%s", exporterBindAddr, exporterPort)

	// Open the TCP port immediately. If the IP doesn't exist on any interface or
	// if the port is already bound by another process, this fails safely here!
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		log.Fatalf("Fatal network error: unable to bind to http://%s/metrics. System reports: %v", bindAddr, err)
	}
	// Do not defer listener.Close() since we want it to stay bound until the program exits.

	log.Printf("Successfully secured network socket on http://%s/metrics before executing kernel modifications.", bindAddr)

	// --- 3. LOAD EBPF OBJECTS ---
	log.Println("Loading and compiling embedded eBPF CO-RE binaries...")
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		listener.Close()
		log.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Populate LPM Trie
	subnets := strings.Split(monitorSubnets, ",")
	for _, cidr := range subnets {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Warning: Invalid CIDR '%s' skipped. (%v)", cidr, err)
			continue
		}
		ones, _ := ipNet.Mask.Size()
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue
		}

		var ipUint uint32
		if isLittleEndian() {
			ipUint = binary.LittleEndian.Uint32(ip4)
		} else {
			ipUint = binary.BigEndian.Uint32(ip4)
		}

		key := bpfLpmKeyV4{
			Prefixlen: uint32(ones),
			Data:      ipUint,
		}
		var val uint32 = 1

		if err := objs.MonitoredSubnets.Put(&key, &val); err != nil {
			log.Fatalf("failed to populate monitored subnets map: %v", err)
		}
		log.Printf("Loaded subnet into eBPF routing trie: %s", cidr)
	}

	// --- 4. NETLINK HOOKS SETUP ---
	link, err := netlink.LinkByName(iface)
	if err != nil {
		log.Fatalf("failed to find interface %s: %v", iface, err)
	}

	log.Printf("Attaching clsact qdisc to %s...", iface)
	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}

	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, os.ErrExist) {
		if !strings.Contains(err.Error(), "file exists") {
			log.Fatalf("failed to create clsact qdisc: %v", err)
		}
	}

	// Ingress Filter Setup
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.CountIngress.FD(),
		Name:         "count_ingress",
		DirectAction: true,
		ClassId:      1,
	}
	if err := netlink.FilterAdd(ingressFilter); err != nil {
		log.Fatalf("failed to add ingress filter: %v", err)
	}

	// Egress Filter Setup
	egressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.CountEgress.FD(),
		Name:         "count_egress",
		DirectAction: true,
		ClassId:      1,
	}
	if err := netlink.FilterAdd(egressFilter); err != nil {
		log.Fatalf("failed to add egress filter: %v", err)
	}

	// Trap termination signal for automatic clean up
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("[Signal %v Caught] Cleaning up TC filters from host interface %s...", sig, iface)
		_ = netlink.QdiscDel(qdisc)
		log.Println("Host interface successfully cleared.")
		os.Exit(0)
	}()

	// --- 5. START HTTP PROMETHEUS METRICS USING PRE-BOUND SOCKET ---
	reg := prometheus.NewRegistry()
	reg.MustRegister(trafficMetric)

	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	log.Printf("Starting Prometheus Metrics Server on %s, Listening loop active.", iface)

	// Pass our existing secure listener directly to http.Serve
	go func() {
		if err := http.Serve(listener, nil); err != nil {
			log.Printf("HTTP Server serving error: %v", err)
		}
	}()

	// --- 6. ATOMIC MAP BATCH COLLECTION LOOP ---
	ticker := time.NewTicker(time.Duration(refreshInterval) * time.Second)
	for range ticker.C {
		trafficMetric.Reset()

		var (
			cursor ebpf.MapBatchCursor
			keys   = make([]uint32, 65535)
			values = make([]bpfStats, 65535)
		)

		count, err := objs.TrafficMap.BatchLookupAndDelete(&cursor, keys, values, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Printf("Error performing batch lookup and delete: %v", err)
			continue
		}

		for i := 0; i < count; i++ {
			ipBytes := make([]byte, 4)
			if isLittleEndian() {
				binary.LittleEndian.PutUint32(ipBytes, keys[i])
			} else {
				binary.BigEndian.PutUint32(ipBytes, keys[i])
			}
			ipStr := net.IP(ipBytes).String()

			trafficMetric.WithLabelValues(ipStr, "rx", iface).Set(float64(values[i].RxBytes))
			trafficMetric.WithLabelValues(ipStr, "tx", iface).Set(float64(values[i].TxBytes))
		}
	}
}
