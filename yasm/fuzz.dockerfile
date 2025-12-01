FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract yasm 1.3.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/yasm/yasm/releases/download/v1.3.0/yasm-1.3.0.tar.gz && \
    tar -xzf yasm-1.3.0.tar.gz && \
    rm yasm-1.3.0.tar.gz

WORKDIR /src/yasm-1.3.0

# Build yasm with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the yasm binary
RUN cp yasm /out/yasm

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf yasm-1.3.0 && \
    wget https://github.com/yasm/yasm/releases/download/v1.3.0/yasm-1.3.0.tar.gz && \
    tar -xzf yasm-1.3.0.tar.gz && \
    rm yasm-1.3.0.tar.gz

WORKDIR /src/yasm-1.3.0

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp yasm /out/yasm.cmplog

# Copy fuzzing resources
COPY yasm/fuzz/dict /out/dict
COPY yasm/fuzz/in /out/in
COPY yasm/fuzz/fuzz.sh /out/fuzz.sh
COPY yasm/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/yasm /out/yasm.cmplog && \
    file /out/yasm && \
    /out/yasm --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing yasm'"]
