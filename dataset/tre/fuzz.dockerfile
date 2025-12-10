FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract tre v0.9.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/laurikari/tre/releases/download/v0.9.0/tre-0.9.0.tar.gz && \
    tar -xzf tre-0.9.0.tar.gz && \
    rm tre-0.9.0.tar.gz

WORKDIR /src/tre-0.9.0

# Build agrep with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the agrep binary
RUN cp src/agrep /out/agrep

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf tre-0.9.0 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/laurikari/tre/releases/download/v0.9.0/tre-0.9.0.tar.gz && \
    tar -xzf tre-0.9.0.tar.gz && \
    rm tre-0.9.0.tar.gz

WORKDIR /src/tre-0.9.0

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/agrep /out/agrep.cmplog

# Copy fuzzing resources
COPY tre/fuzz/dict /out/dict
COPY tre/fuzz/in /out/in
COPY tre/fuzz/fuzz.sh /out/fuzz.sh
COPY tre/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/agrep /out/agrep.cmplog && \
    file /out/agrep && \
    /out/agrep --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tre agrep'"]
