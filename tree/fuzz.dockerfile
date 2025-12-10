FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract tree 2.1.3 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/Old-Man-Programmer/tree/archive/refs/tags/2.1.3.tar.gz && \
    tar -xzf 2.1.3.tar.gz && \
    rm 2.1.3.tar.gz

WORKDIR /src/tree-2.1.3

# Build tree with afl-clang-lto for fuzzing
RUN make CC=afl-clang-lto LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Install the tree binary
RUN cp tree /out/tree

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf tree-2.1.3 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/Old-Man-Programmer/tree/archive/refs/tags/2.1.3.tar.gz && \
    tar -xzf 2.1.3.tar.gz && \
    rm 2.1.3.tar.gz

WORKDIR /src/tree-2.1.3

RUN make CC=afl-clang-lto LDFLAGS="-static -Wl,--allow-multiple-definition" AFL_LLVM_CMPLOG=1 -j$(nproc)

# Install CMPLOG binary
RUN cp tree /out/tree.cmplog

# Copy fuzzing resources
COPY tree/fuzz/dict /out/dict
COPY tree/fuzz/in /out/in
COPY tree/fuzz/fuzz.sh /out/fuzz.sh
COPY tree/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/tree /out/tree.cmplog && \
    file /out/tree && \
    /out/tree --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tree'"]
