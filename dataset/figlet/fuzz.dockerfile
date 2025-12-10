FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract figlet v2.2.5 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cmatsuoka/figlet/archive/refs/tags/2.2.5.tar.gz -O figlet-2.2.5.tar.gz && \
    tar -xzf figlet-2.2.5.tar.gz && \
    rm figlet-2.2.5.tar.gz

WORKDIR /src/figlet-2.2.5

# Build figlet with afl-clang-lto for fuzzing
# Override both CC and LD since Makefile uses separate LD variable
RUN make CC=afl-clang-lto \
    LD=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Install the figlet binary
RUN cp figlet /out/figlet

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf figlet-2.2.5 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cmatsuoka/figlet/archive/refs/tags/2.2.5.tar.gz -O figlet-2.2.5.tar.gz && \
    tar -xzf figlet-2.2.5.tar.gz && \
    rm figlet-2.2.5.tar.gz

WORKDIR /src/figlet-2.2.5

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    LD=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Install CMPLOG binary
RUN cp figlet /out/figlet.cmplog

# Copy fuzzing resources
COPY figlet/fuzz/dict /out/dict
COPY figlet/fuzz/in /out/in
COPY figlet/fuzz/fuzz.sh /out/fuzz.sh
COPY figlet/fuzz/whatsup.sh /out/whatsup.sh

# Copy font files for figlet
RUN cp -r fonts /out/fonts

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/figlet /out/figlet.cmplog && \
    file /out/figlet && \
    echo "Test" | FIGLET_FONTDIR=/out/fonts /out/figlet

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing figlet'"]
