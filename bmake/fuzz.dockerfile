FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract bmake v20251111 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 http://www.crufty.net/ftp/pub/sjg/bmake-20251111.tar.gz && \
    tar -xzf bmake-20251111.tar.gz && \
    rm bmake-20251111.tar.gz

WORKDIR /src/bmake

# Build bmake with afl-clang-lto for fuzzing (main target binary)
# Use static linking for better portability
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure && \
    sh ./make-bootstrap.sh

# Install the bmake binary
RUN cp bmake /out/bmake

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf bmake && \
    wget --tries=3 --retry-connrefused --waitretry=5 http://www.crufty.net/ftp/pub/sjg/bmake-20251111.tar.gz && \
    tar -xzf bmake-20251111.tar.gz && \
    rm bmake-20251111.tar.gz

WORKDIR /src/bmake

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure && \
    AFL_LLVM_CMPLOG=1 sh ./make-bootstrap.sh

# Install CMPLOG binary
RUN cp bmake /out/bmake.cmplog

# Copy fuzzing resources
COPY bmake/fuzz/dict /out/dict
COPY bmake/fuzz/in /out/in
COPY bmake/fuzz/fuzz.sh /out/fuzz.sh
COPY bmake/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/bmake /out/bmake.cmplog && \
    file /out/bmake

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing bmake'"]
