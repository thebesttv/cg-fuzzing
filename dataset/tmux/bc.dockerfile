FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tmux 3.6

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: tmux" > /work/proj && \
    echo "version: 3.6" >> /work/proj && \
    echo "source: https://github.com/tmux/tmux/releases/download/3.6/tmux-3.6.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/tmux/tmux/releases/download/3.6/tmux-3.6.tar.gz && \
    tar -xzf tmux-3.6.tar.gz && \
    mv tmux-3.6 build && \
    rm tmux-3.6.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
    file \
    libevent-dev \
    libncurses-dev \
    bison \
    pkg-config \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure and build tmux with WLLVM
# Note: tmux needs libevent and ncurses, so we'll link statically where possible
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --enable-static

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc tmux && \
    mv tmux.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
