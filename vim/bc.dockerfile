FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract vim v9.1.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz && \
    tar -xzf v9.1.0.tar.gz && \
    rm v9.1.0.tar.gz

WORKDIR /home/SVF-tools/vim-9.1.0

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
RUN mkdir -p ~/bc && \
    extract-bc src/vim && \
    mv src/vim.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
