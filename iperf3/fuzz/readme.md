# iperf3 Fuzzing Resources

## External Resources

- dict: Created based on iperf3 command line options
- in/: Created with basic command line inputs

## Usage

```bash
docker build -f iperf3/fuzz.dockerfile -t iperf3-fuzz .
docker run -it --rm iperf3-fuzz ./fuzz.sh
```

## About iperf3

iperf3 is a tool for active measurements of the maximum achievable bandwidth on IP networks. It supports tuning of various parameters related to timing, buffers and protocols (TCP, UDP, SCTP with IPv4 and IPv6).
