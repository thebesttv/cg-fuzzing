FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract vim v9.1.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz && \
    tar -xzf v9.1.0.tar.gz && \
    rm v9.1.0.tar.gz

WORKDIR /src/vim-9.1.0

# Build vim with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
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

RUN make -j$(nproc)

# Install the vim binary
RUN cp src/vim /out/vim

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf vim-9.1.0 && \
    wget https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz && \
    tar -xzf v9.1.0.tar.gz && \
    rm v9.1.0.tar.gz

WORKDIR /src/vim-9.1.0

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
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

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/vim /out/vim.cmplog

# Copy fuzzing resources
COPY dataset/vim/fuzz/dict /out/dict
COPY dataset/vim/fuzz/in /out/in
COPY dataset/vim/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/vim/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/vim /out/vim.cmplog && \
    file /out/vim && \
    /out/vim --version | head -5

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing vim'"]
