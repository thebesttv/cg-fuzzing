FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract unrtf 0.21.10 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/unrtf/unrtf-0.21.10.tar.gz && \
    tar -xzf unrtf-0.21.10.tar.gz && \
    rm unrtf-0.21.10.tar.gz

WORKDIR /src/unrtf-0.21.10

# Build unrtf with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the binary
RUN cp src/unrtf /out/unrtf

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf unrtf-0.21.10 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/unrtf/unrtf-0.21.10.tar.gz && \
    tar -xzf unrtf-0.21.10.tar.gz && \
    rm unrtf-0.21.10.tar.gz

WORKDIR /src/unrtf-0.21.10

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/unrtf /out/unrtf.cmplog

# Copy fuzzing resources
COPY unrtf/fuzz/dict /out/dict
COPY unrtf/fuzz/in /out/in
COPY unrtf/fuzz/fuzz.sh /out/fuzz.sh
COPY unrtf/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/unrtf /out/unrtf.cmplog && \
    file /out/unrtf && \
    /out/unrtf --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing unrtf'"]
