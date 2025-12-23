FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract less v668

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: less" > /work/proj && \
    echo "version: 668" >> /work/proj && \
    echo "source: https://greenwoodsoftware.com/less/less-668.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://greenwoodsoftware.com/less/less-668.tar.gz && \
    tar -xzf less-668.tar.gz && \
    mv less-668 build && \
    rm less-668.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, ncurses for less)
RUN apt-get update && \
    apt-get install -y file libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --with-regex=posix

# Build less
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc less && \
    mv less.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
