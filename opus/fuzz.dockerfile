FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract opus v1.5.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/opus/releases/download/v1.5.2/opus-1.5.2.tar.gz && \
    tar -xzf opus-1.5.2.tar.gz && \
    rm opus-1.5.2.tar.gz

WORKDIR /src/opus-1.5.2

# Configure with afl-clang-fast
RUN CC=afl-clang-fast \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-doc

# Build opus library and demo tools
RUN make -j$(nproc)

# Copy binary
RUN cp opus_demo /out/opus_demo

# Build CMPLOG version
WORKDIR /src
RUN rm -rf opus-1.5.2 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/opus/releases/download/v1.5.2/opus-1.5.2.tar.gz && \
    tar -xzf opus-1.5.2.tar.gz && \
    rm opus-1.5.2.tar.gz

WORKDIR /src/opus-1.5.2

# Configure with afl-clang-fast and CMPLOG
RUN CC=afl-clang-fast \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --disable-doc

# Build opus library and demo tools
RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp opus_demo /out/opus_demo.cmplog

# Copy fuzzing resources
COPY opus/fuzz/dict /out/dict
COPY opus/fuzz/in /out/in
COPY opus/fuzz/fuzz.sh /out/fuzz.sh
COPY opus/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/opus_demo /out/opus_demo.cmplog && \
    file /out/opus_demo

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing opus'"]
