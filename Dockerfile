# --- Stage 1: Build Environment ---
FROM golang:trixie AS builder

# Install the required build tool for eBPF code generation (bpftool)
RUN apt-get update && \
    apt-get install -y \
        clang \
        llvm \
        make \
        bpftool \
        libelf-dev \
        libbpf-dev

WORKDIR /src

# Copy ONLY your 3 core source files into the container
COPY Makefile counter.bpf.c main.go ./

# Initialize and tidy the Go module inside the container automatically
RUN go mod init gomontraff && go mod tidy

# Run your Makefile to extract vmlinux.h, run bpf2go, and build the 'gomontraff' binary
RUN make

# --- Stage 2: Ultra-lite Runtime Environment ---
FROM scratch

# Copy the compiled standalone static binary from the builder stage
COPY --from=builder /src/gomontraff /gomontraff

# Force the process name to match the binary name on execution
ENTRYPOINT ["/gomontraff"]
