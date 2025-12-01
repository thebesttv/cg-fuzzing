FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract lzo 2.10 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz && \
    tar -xzf lzo-2.10.tar.gz && \
    rm lzo-2.10.tar.gz

WORKDIR /src/lzo-2.10

# Build lzo with afl-clang-lto
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Build lzopack example with afl-clang-lto
RUN cd examples && \
    afl-clang-lto -O2 -I. -I../include -I.. -static -Wl,--allow-multiple-definition \
        -o lzopack lzopack.c ../src/.libs/liblzo2.a

# Copy binary to output
RUN cp examples/lzopack /out/lzopack

# Build CMPLOG version
WORKDIR /src
RUN rm -rf lzo-2.10 && \
    wget https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz && \
    tar -xzf lzo-2.10.tar.gz && \
    rm lzo-2.10.tar.gz

WORKDIR /src/lzo-2.10

RUN CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build lzopack CMPLOG version
RUN cd examples && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I. -I../include -I.. -static -Wl,--allow-multiple-definition \
        -o lzopack.cmplog lzopack.c ../src/.libs/liblzo2.a

# Copy CMPLOG binary
RUN cp examples/lzopack.cmplog /out/lzopack.cmplog

# Copy fuzzing resources
COPY lzo/fuzz/dict /out/dict
COPY lzo/fuzz/in /out/in
COPY lzo/fuzz/fuzz.sh /out/fuzz.sh
COPY lzo/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/lzopack /out/lzopack.cmplog && \
    file /out/lzopack && \
    /out/lzopack || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing lzo'"]
