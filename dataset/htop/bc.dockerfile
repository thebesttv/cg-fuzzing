FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract htop 3.4.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: htop" > /work/proj && \
    echo "version: 3.4.1" >> /work/proj && \
    echo "source: https://github.com/htop-dev/htop/releases/download/3.4.1/htop-3.4.1.tar.xz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/htop-dev/htop/releases/download/3.4.1/htop-3.4.1.tar.xz && \
    tar -xf htop-3.4.1.tar.xz && \
    mv htop-3.4.1 build && \
    rm htop-3.4.1.tar.xz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libncurses-dev pkg-config autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --disable-unicode

# Build htop
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    for bin in htop; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" /work/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la /work/bc/
