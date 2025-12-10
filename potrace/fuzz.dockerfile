FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract potrace 1.16 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://potrace.sourceforge.net/download/1.16/potrace-1.16.tar.gz && \
    tar -xzf potrace-1.16.tar.gz && \
    rm potrace-1.16.tar.gz

WORKDIR /src/potrace-1.16

# Build potrace with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the binaries
RUN cp src/potrace /out/potrace

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf potrace-1.16 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://potrace.sourceforge.net/download/1.16/potrace-1.16.tar.gz && \
    tar -xzf potrace-1.16.tar.gz && \
    rm potrace-1.16.tar.gz

WORKDIR /src/potrace-1.16

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/potrace /out/potrace.cmplog

# Copy fuzzing resources
COPY potrace/fuzz/dict /out/dict
COPY potrace/fuzz/in /out/in
COPY potrace/fuzz/fuzz.sh /out/fuzz.sh
COPY potrace/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/potrace /out/potrace.cmplog && \
    file /out/potrace && \
    /out/potrace --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing potrace'"]
