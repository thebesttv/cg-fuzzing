# tcpdump Fuzzing Resources

This directory contains resources for fuzzing tcpdump using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (network protocol keywords)
- `in/` - Initial input corpus (minimal PCAP files: ICMP, TCP)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is custom-created based on:
- Ethernet frame types and protocols
- IP protocol numbers
- TCP/UDP common ports
- ICMP message types
- DNS, HTTP, ARP, VLAN, MPLS, GRE headers
- IPv6 extension headers

The initial input corpus contains minimal valid PCAP files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f tcpdump/fuzz.dockerfile -t tcpdump-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm tcpdump-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm tcpdump-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress (in another terminal):
```bash
docker exec -it <container_id> ./whatsup.sh
# or watch mode:
docker exec -it <container_id> ./whatsup.sh -w
```

## Fuzzing Strategy

- **Target**: tcpdump CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: PCAP files processed with `-nr` (no name resolution, read from file)
- **Static linking**: For better performance and reproducibility
- **Dependencies**: Built with statically linked libpcap

## Version

This fuzzing setup uses tcpdump version 4.99.5 and libpcap version 1.10.5, matching the bc.dockerfile.
