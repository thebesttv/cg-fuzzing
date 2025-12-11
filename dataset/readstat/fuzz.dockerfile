FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract readstat v1.1.9 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 \
    https://github.com/WizardMac/ReadStat/releases/download/v1.1.9/readstat-1.1.9.tar.gz && \
    tar -xzf readstat-1.1.9.tar.gz && \
    rm readstat-1.1.9.tar.gz

WORKDIR /src/readstat-1.1.9

# Build readstat with afl-clang-lto for fuzzing (main target binary)
# Use static linking and disable strict-prototypes warning
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -Wno-strict-prototypes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Install the readstat binary
RUN cp readstat /out/readstat

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf readstat-1.1.9 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 \
    https://github.com/WizardMac/ReadStat/releases/download/v1.1.9/readstat-1.1.9.tar.gz && \
    tar -xzf readstat-1.1.9.tar.gz && \
    rm readstat-1.1.9.tar.gz

WORKDIR /src/readstat-1.1.9

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -Wno-strict-prototypes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp readstat /out/readstat.cmplog

# Copy fuzzing resources
COPY readstat/fuzz/dict /out/dict
COPY readstat/fuzz/in /out/in
COPY readstat/fuzz/fuzz.sh /out/fuzz.sh
COPY readstat/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/readstat /out/readstat.cmplog && \
    file /out/readstat && \
    /out/readstat --help || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing readstat'"]
