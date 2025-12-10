FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract ncdu 1.22 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://dev.yorhel.nl/download/ncdu-1.22.tar.gz && \
    tar -xzf ncdu-1.22.tar.gz && \
    rm ncdu-1.22.tar.gz

WORKDIR /src/ncdu-1.22

# Build ncdu with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the ncdu binary
RUN cp ncdu /out/ncdu

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf ncdu-1.22 && \
    wget https://dev.yorhel.nl/download/ncdu-1.22.tar.gz && \
    tar -xzf ncdu-1.22.tar.gz && \
    rm ncdu-1.22.tar.gz

WORKDIR /src/ncdu-1.22

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp ncdu /out/ncdu.cmplog

# Copy fuzzing resources
COPY ncdu/fuzz/dict /out/dict
COPY ncdu/fuzz/in /out/in
COPY ncdu/fuzz/fuzz.sh /out/fuzz.sh
COPY ncdu/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/ncdu /out/ncdu.cmplog && \
    file /out/ncdu && \
    /out/ncdu --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing ncdu'"]
