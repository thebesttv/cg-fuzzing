FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract qbe (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://c9x.me/compile/release/qbe-1.2.tar.xz && \
    tar -xJf qbe-1.2.tar.xz && \
    rm qbe-1.2.tar.xz

WORKDIR /src/qbe-1.2

# Build with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

# Install the qbe binary
RUN cp qbe /out/qbe

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf qbe-1.2 && \
    wget https://c9x.me/compile/release/qbe-1.2.tar.xz && \
    tar -xJf qbe-1.2.tar.xz && \
    rm qbe-1.2.tar.xz

WORKDIR /src/qbe-1.2

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc)

# Install CMPLOG binary
RUN cp qbe /out/qbe.cmplog

# Copy fuzzing resources
COPY qbe/fuzz/dict /out/dict
COPY qbe/fuzz/in /out/in
COPY qbe/fuzz/fuzz.sh /out/fuzz.sh
COPY qbe/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/qbe /out/qbe.cmplog && \
    file /out/qbe && \
    /out/qbe -h || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing qbe'"]
