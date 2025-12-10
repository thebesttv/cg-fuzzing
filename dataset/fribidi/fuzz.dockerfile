FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract fribidi (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/fribidi/fribidi/releases/download/v1.0.15/fribidi-1.0.15.tar.xz && \
    tar -xf fribidi-1.0.15.tar.xz && \
    rm fribidi-1.0.15.tar.xz

WORKDIR /src/fribidi-1.0.15

# Build with afl-clang-lto
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)
RUN cp bin/fribidi /out/fribidi

# Build CMPLOG version
WORKDIR /src
RUN rm -rf fribidi-1.0.15 && \
    wget https://github.com/fribidi/fribidi/releases/download/v1.0.15/fribidi-1.0.15.tar.xz && \
    tar -xf fribidi-1.0.15.tar.xz && \
    rm fribidi-1.0.15.tar.xz

WORKDIR /src/fribidi-1.0.15

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp bin/fribidi /out/fribidi.cmplog

# Copy fuzzing resources
COPY fribidi/fuzz/dict /out/dict
COPY fribidi/fuzz/in /out/in
COPY fribidi/fuzz/fuzz.sh /out/fuzz.sh
COPY fribidi/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/fribidi /out/fribidi.cmplog && \
    file /out/fribidi && \
    /out/fribidi --version

# Default command
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing fribidi'"]
