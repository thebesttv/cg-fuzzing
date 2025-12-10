FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract chibicc (same version as bc.dockerfile - main branch)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/rui314/chibicc/archive/refs/heads/main.tar.gz -O chibicc.tar.gz && \
    tar -xzf chibicc.tar.gz && \
    rm chibicc.tar.gz

WORKDIR /src/chibicc-main

# Build chibicc with afl-clang-lto for fuzzing (main target binary)
RUN make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Install the chibicc binary
RUN cp chibicc /out/chibicc

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf chibicc-main && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/rui314/chibicc/archive/refs/heads/main.tar.gz -O chibicc.tar.gz && \
    tar -xzf chibicc.tar.gz && \
    rm chibicc.tar.gz

WORKDIR /src/chibicc-main

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Install CMPLOG binary
RUN cp chibicc /out/chibicc.cmplog

# Copy fuzzing resources
COPY chibicc/fuzz/dict /out/dict
COPY chibicc/fuzz/in /out/in
COPY chibicc/fuzz/fuzz.sh /out/fuzz.sh
COPY chibicc/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/chibicc /out/chibicc.cmplog && \
    file /out/chibicc

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing chibicc'"]
