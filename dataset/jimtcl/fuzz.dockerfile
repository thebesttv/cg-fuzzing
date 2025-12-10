FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract jimtcl 0.83 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/msteveb/jimtcl/archive/refs/tags/0.83.tar.gz && \
    tar -xzf 0.83.tar.gz && \
    rm 0.83.tar.gz

WORKDIR /src/jimtcl-0.83

# Configure with afl-clang-lto and static linking
# Disable SSL to avoid static linking issues
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-ssl

# Build jimtcl
RUN make -j$(nproc)

# Copy the jimsh binary
RUN cp jimsh /out/jimsh

# Build CMPLOG version
WORKDIR /src
RUN rm -rf jimtcl-0.83 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/msteveb/jimtcl/archive/refs/tags/0.83.tar.gz && \
    tar -xzf 0.83.tar.gz && \
    rm 0.83.tar.gz

WORKDIR /src/jimtcl-0.83

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-ssl

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN cp jimsh /out/jimsh.cmplog

# Copy fuzzing resources
COPY jimtcl/fuzz/dict /out/dict
COPY jimtcl/fuzz/in /out/in
COPY jimtcl/fuzz/fuzz.sh /out/fuzz.sh
COPY jimtcl/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/jimsh /out/jimsh.cmplog && \
    file /out/jimsh && \
    echo "puts hello" | /out/jimsh

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing jimtcl'"]
