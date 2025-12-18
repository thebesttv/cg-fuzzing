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
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/tmux/tmux/releases/download/3.6/tmux-3.6.tar.gz && \
    tar -xzf tmux-3.6.tar.gz && \
    rm tmux-3.6.tar.gz

WORKDIR /home/SVF-tools/tmux-3.6

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
RUN mkdir -p ~/bc && \
    extract-bc tmux && \
    mv tmux.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
