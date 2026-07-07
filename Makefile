TARGET := gomontraff
BPF_SRC := counter.bpf.c

.PHONY: all generate build clean vmlinux

all: generate build

vmlinux:
	@echo "Extracting CO-RE vmlinux.h header file from working kernel..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

generate: vmlinux
	@echo "Running bpf2go compilation tooling..."
	@go generate ./...

build:
	@echo "Building static, production-grade Go executable binary..."
	@CGO_ENABLED=0 go build -ldflags="-w -s" -o $(TARGET) .

clean:
	@echo "Cleaning artifacts..."
	@rm -f vmlinux.h bpf_bpfeb.go bpf_bpfel.go bpf_bpfeb.o bpf_bpfel.o $(TARGET)
