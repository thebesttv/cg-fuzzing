FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract gperf 3.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/gperf/gperf-3.1.tar.gz && \
    tar -xzf gperf-3.1.tar.gz && \
    rm gperf-3.1.tar.gz

WORKDIR /src/gperf-3.1

# Build gperf with afl-clang-lto for fuzzing (main target binary)
# -Wno-register to suppress C++17 register keyword error
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2 -Wno-register" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the gperf binary
RUN cp src/gperf /out/gperf

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf gperf-3.1 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/gperf/gperf-3.1.tar.gz && \
    tar -xzf gperf-3.1.tar.gz && \
    rm gperf-3.1.tar.gz

WORKDIR /src/gperf-3.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2 -Wno-register" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/gperf /out/gperf.cmplog

# Copy fuzzing resources
COPY gperf/fuzz/dict /out/dict
COPY gperf/fuzz/in /out/in
COPY gperf/fuzz/fuzz.sh /out/fuzz.sh
COPY gperf/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/gperf /out/gperf.cmplog && \
    file /out/gperf && \
    /out/gperf --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing gperf'"]
