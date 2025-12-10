FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract gifsicle v1.96 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://www.lcdf.org/gifsicle/gifsicle-1.96.tar.gz && \
    tar -xzf gifsicle-1.96.tar.gz && \
    rm gifsicle-1.96.tar.gz

WORKDIR /src/gifsicle-1.96

# Build gifsicle with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the gifsicle binary
RUN cp src/gifsicle /out/gifsicle

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf gifsicle-1.96 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://www.lcdf.org/gifsicle/gifsicle-1.96.tar.gz && \
    tar -xzf gifsicle-1.96.tar.gz && \
    rm gifsicle-1.96.tar.gz

WORKDIR /src/gifsicle-1.96

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/gifsicle /out/gifsicle.cmplog

# Copy fuzzing resources
COPY gifsicle/fuzz/dict /out/dict
COPY gifsicle/fuzz/in /out/in
COPY gifsicle/fuzz/fuzz.sh /out/fuzz.sh
COPY gifsicle/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/gifsicle /out/gifsicle.cmplog && \
    file /out/gifsicle && \
    /out/gifsicle --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing gifsicle'"]
