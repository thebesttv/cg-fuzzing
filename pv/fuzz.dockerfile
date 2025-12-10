FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract pv 1.9.7 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.ivarch.com/programs/sources/pv-1.9.7.tar.gz && \
    tar -xzf pv-1.9.7.tar.gz && \
    rm pv-1.9.7.tar.gz

WORKDIR /src/pv-1.9.7

# Build with afl-clang-lto
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)
RUN cp pv /out/pv

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf pv-1.9.7 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.ivarch.com/programs/sources/pv-1.9.7.tar.gz && \
    tar -xzf pv-1.9.7.tar.gz && \
    rm pv-1.9.7.tar.gz

WORKDIR /src/pv-1.9.7

RUN AFL_LLVM_CMPLOG=1 CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp pv /out/pv.cmplog

# Copy fuzzing resources
COPY pv/fuzz/dict /out/dict
COPY pv/fuzz/in /out/in
COPY pv/fuzz/fuzz.sh /out/fuzz.sh
COPY pv/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/pv /out/pv.cmplog && \
    file /out/pv && \
    /out/pv --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing pv'"]
