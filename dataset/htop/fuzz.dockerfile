FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev pkg-config autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract htop 3.4.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/htop-dev/htop/releases/download/3.4.1/htop-3.4.1.tar.xz && \
    tar -xf htop-3.4.1.tar.xz && \
    rm htop-3.4.1.tar.xz

WORKDIR /src/htop-3.4.1

# Build htop with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-unicode

RUN make -j$(nproc)

# Install the htop binary
RUN cp htop /out/htop

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf htop-3.4.1 && \
    wget https://github.com/htop-dev/htop/releases/download/3.4.1/htop-3.4.1.tar.xz && \
    tar -xf htop-3.4.1.tar.xz && \
    rm htop-3.4.1.tar.xz

WORKDIR /src/htop-3.4.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --disable-unicode

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp htop /out/htop.cmplog

# Copy fuzzing resources
COPY htop/fuzz/dict /out/dict
COPY htop/fuzz/in /out/in
COPY htop/fuzz/fuzz.sh /out/fuzz.sh
COPY htop/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/htop /out/htop.cmplog && \
    file /out/htop && \
    /out/htop --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing htop'"]
