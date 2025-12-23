FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract vim v9.1.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: vim" > /work/proj && \
    echo "version: 9.1.0" >> /work/proj && \
    echo "source: https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz && \
    tar -xzf v9.1.0.tar.gz && \
    mv v9.1.0 build && \
    rm v9.1.0.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Build minimal vim without GUI features
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --disable-gui \
        --disable-gtktest \
        --disable-xim \
        --disable-netbeans \
        --disable-channel \
        --without-x \
        --enable-multibyte

# Build vim
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/vim && \
    mv src/vim.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
