FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract pigz v2.8 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/madler/pigz/archive/refs/tags/v2.8.tar.gz && \
    tar -xzf v2.8.tar.gz && \
    rm v2.8.tar.gz

WORKDIR /src/pigz-2.8

# Build pigz with afl-clang-lto for fuzzing (main target binary)
# Use static linking
RUN make clean || true && \
    make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Copy main binary
RUN cp pigz /out/pigz

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf pigz-2.8 && \
    wget https://github.com/madler/pigz/archive/refs/tags/v2.8.tar.gz && \
    tar -xzf v2.8.tar.gz && \
    rm v2.8.tar.gz

WORKDIR /src/pigz-2.8

RUN make clean || true && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Copy CMPLOG binary
RUN cp pigz /out/pigz.cmplog

# Copy fuzzing resources
COPY pigz/fuzz/dict /out/dict
COPY pigz/fuzz/in /out/in
COPY pigz/fuzz/fuzz.sh /out/fuzz.sh
COPY pigz/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/pigz /out/pigz.cmplog && \
    file /out/pigz && \
    /out/pigz --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing pigz'"]
