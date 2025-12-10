FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract xxHash v0.8.3 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/Cyan4973/xxHash/archive/refs/tags/v0.8.3.tar.gz && \
    tar -xzf v0.8.3.tar.gz && \
    rm v0.8.3.tar.gz

WORKDIR /src/xxHash-0.8.3

# Build xxhsum with afl-clang-lto for fuzzing (main target binary)
RUN make clean || true && \
    make -j$(nproc) \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    xxhsum

# Install the xxhsum binary
RUN cp xxhsum /out/xxhsum

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf xxHash-0.8.3 && \
    wget https://github.com/Cyan4973/xxHash/archive/refs/tags/v0.8.3.tar.gz && \
    tar -xzf v0.8.3.tar.gz && \
    rm v0.8.3.tar.gz

WORKDIR /src/xxHash-0.8.3

RUN make clean || true && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    xxhsum

# Install CMPLOG binary
RUN cp xxhsum /out/xxhsum.cmplog

# Copy fuzzing resources
COPY xxhash/fuzz/dict /out/dict
COPY xxhash/fuzz/in /out/in
COPY xxhash/fuzz/fuzz.sh /out/fuzz.sh
COPY xxhash/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/xxhsum /out/xxhsum.cmplog && \
    file /out/xxhsum && \
    /out/xxhsum --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing xxhsum'"]
