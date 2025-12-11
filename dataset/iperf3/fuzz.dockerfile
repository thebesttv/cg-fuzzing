FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract iperf3 v3.17.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/esnet/iperf/releases/download/3.17.1/iperf-3.17.1.tar.gz && \
    tar -xzf iperf-3.17.1.tar.gz && \
    rm iperf-3.17.1.tar.gz

WORKDIR /src/iperf-3.17.1

# Build iperf3 with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the iperf3 binary
RUN cp src/iperf3 /out/iperf3

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf iperf-3.17.1 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/esnet/iperf/releases/download/3.17.1/iperf-3.17.1.tar.gz && \
    tar -xzf iperf-3.17.1.tar.gz && \
    rm iperf-3.17.1.tar.gz

WORKDIR /src/iperf-3.17.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/iperf3 /out/iperf3.cmplog

# Copy fuzzing resources
COPY iperf3/fuzz/dict /out/dict
COPY iperf3/fuzz/in /out/in
COPY iperf3/fuzz/fuzz.sh /out/fuzz.sh
COPY iperf3/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/iperf3 /out/iperf3.cmplog && \
    file /out/iperf3

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing iperf3'"]
