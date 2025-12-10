FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract tinycbor v0.6.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/intel/tinycbor/archive/refs/tags/v0.6.1.tar.gz && \
    tar -xzf v0.6.1.tar.gz && \
    rm v0.6.1.tar.gz

WORKDIR /src/tinycbor-0.6.1

# Build with afl-clang-lto for fuzzing
RUN make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    BUILD_SHARED=0 \
    BUILD_STATIC=1 \
    -j$(nproc)

# Install the cbordump binary
RUN cp bin/cbordump /out/cbordump

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf tinycbor-0.6.1 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/intel/tinycbor/archive/refs/tags/v0.6.1.tar.gz && \
    tar -xzf v0.6.1.tar.gz && \
    rm v0.6.1.tar.gz

WORKDIR /src/tinycbor-0.6.1

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    BUILD_SHARED=0 \
    BUILD_STATIC=1 \
    -j$(nproc)

# Install CMPLOG binary
RUN cp bin/cbordump /out/cbordump.cmplog

# Copy fuzzing resources
COPY tinycbor/fuzz/dict /out/dict
COPY tinycbor/fuzz/in /out/in
COPY tinycbor/fuzz/fuzz.sh /out/fuzz.sh
COPY tinycbor/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/cbordump /out/cbordump.cmplog && \
    file /out/cbordump

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tinycbor'"]
