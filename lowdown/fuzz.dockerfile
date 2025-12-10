FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract lowdown 1.1.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/kristapsdz/lowdown/archive/refs/tags/VERSION_1_1_0.tar.gz && \
    tar -xzf VERSION_1_1_0.tar.gz && \
    rm VERSION_1_1_0.tar.gz

WORKDIR /src/lowdown-VERSION_1_1_0

# Configure and build lowdown with afl-clang-lto for fuzzing
RUN ./configure

RUN make lowdown CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)
RUN cp lowdown /out/lowdown

# Build CMPLOG version
WORKDIR /src
RUN rm -rf lowdown-VERSION_1_1_0 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/kristapsdz/lowdown/archive/refs/tags/VERSION_1_1_0.tar.gz && \
    tar -xzf VERSION_1_1_0.tar.gz && \
    rm VERSION_1_1_0.tar.gz

WORKDIR /src/lowdown-VERSION_1_1_0

RUN ./configure

RUN AFL_LLVM_CMPLOG=1 make lowdown CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)
RUN cp lowdown /out/lowdown.cmplog

# Copy fuzzing resources (lowdown includes AFL resources)
COPY lowdown/fuzz/dict /out/dict
COPY lowdown/fuzz/in /out/in
COPY lowdown/fuzz/fuzz.sh /out/fuzz.sh
COPY lowdown/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/lowdown /out/lowdown.cmplog && \
    file /out/lowdown

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing lowdown'"]
