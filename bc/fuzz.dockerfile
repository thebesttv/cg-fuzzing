FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget flex bison ed texinfo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract GNU bc 1.08.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/bc/bc-1.08.2.tar.gz && \
    tar -xzf bc-1.08.2.tar.gz && \
    rm bc-1.08.2.tar.gz

WORKDIR /src/bc-1.08.2

# Build bc with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the bc binary
RUN cp bc/bc /out/bc

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf bc-1.08.2 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/bc/bc-1.08.2.tar.gz && \
    tar -xzf bc-1.08.2.tar.gz && \
    rm bc-1.08.2.tar.gz

WORKDIR /src/bc-1.08.2

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp bc/bc /out/bc.cmplog

# Copy fuzzing resources
COPY bc/fuzz/dict /out/dict
COPY bc/fuzz/in /out/in
COPY bc/fuzz/fuzz.sh /out/fuzz.sh
COPY bc/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/bc /out/bc.cmplog && \
    file /out/bc && \
    echo "1+1" | /out/bc

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing bc'"]
