FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
    wget \
    libevent-dev \
    libncurses-dev \
    bison \
    pkg-config \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract tmux 3.6 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/tmux/tmux/releases/download/3.6/tmux-3.6.tar.gz && \
    tar -xzf tmux-3.6.tar.gz && \
    rm tmux-3.6.tar.gz

WORKDIR /src/tmux-3.6

# Build tmux with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --enable-static

RUN make -j$(nproc)

# Install the tmux binary
RUN cp tmux /out/tmux

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf tmux-3.6 && \
    wget https://github.com/tmux/tmux/releases/download/3.6/tmux-3.6.tar.gz && \
    tar -xzf tmux-3.6.tar.gz && \
    rm tmux-3.6.tar.gz

WORKDIR /src/tmux-3.6

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp tmux /out/tmux.cmplog

# Copy fuzzing resources
COPY dataset/tmux/fuzz/dict /out/dict
COPY dataset/tmux/fuzz/in /out/in
COPY dataset/tmux/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/tmux/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/tmux /out/tmux.cmplog && \
    file /out/tmux && \
    /out/tmux -V

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tmux'"]
