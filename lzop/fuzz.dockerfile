FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and build lzo library (dependency)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz && \
    tar -xzf lzo-2.10.tar.gz && \
    rm lzo-2.10.tar.gz

WORKDIR /src/lzo-2.10

# Build lzo with afl-clang-lto
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)
RUN make install

# Download lzop (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://www.lzop.org/download/lzop-1.04.tar.gz && \
    tar -xzf lzop-1.04.tar.gz && \
    rm lzop-1.04.tar.gz

WORKDIR /src/lzop-1.04

# Build lzop with afl-clang-lto
# Need to specify library path since lzo was installed to /usr/local
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -I/usr/local/include" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -L/usr/local/lib" \
    ./configure --disable-asm

RUN make -j$(nproc)
RUN cp src/lzop /out/lzop

# Build CMPLOG version
WORKDIR /src
RUN rm -rf lzop-1.04 lzo-2.10

# Rebuild lzo with CMPLOG
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz && \
    tar -xzf lzo-2.10.tar.gz && \
    rm lzo-2.10.tar.gz

WORKDIR /src/lzo-2.10

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN make install

# Download and build lzop with CMPLOG
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://www.lzop.org/download/lzop-1.04.tar.gz && \
    tar -xzf lzop-1.04.tar.gz && \
    rm lzop-1.04.tar.gz

WORKDIR /src/lzop-1.04

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -I/usr/local/include" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -L/usr/local/lib" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-asm

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp src/lzop /out/lzop.cmplog

# Copy fuzzing resources
COPY lzop/fuzz/dict /out/dict
COPY lzop/fuzz/in /out/in
COPY lzop/fuzz/fuzz.sh /out/fuzz.sh
COPY lzop/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/lzop /out/lzop.cmplog && \
    file /out/lzop && \
    /out/lzop --version

# Default command
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing lzop'"]
