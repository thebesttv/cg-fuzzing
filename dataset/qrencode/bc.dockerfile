FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libqrencode v4.1.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: qrencode" > /work/proj && \
    echo "version: 4.1.1" >> /work/proj && \
    echo "source: https://github.com/fukuchi/libqrencode/archive/refs/tags/v4.1.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/fukuchi/libqrencode/archive/refs/tags/v4.1.1.tar.gz && \
    tar -xzf v4.1.1.tar.gz && \
    mv v4.1.1 build && \
    rm v4.1.1.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, autotools for build)
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool pkg-config libpng-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Generate configure script
RUN autoreconf -i

# Configure with static linking and WLLVM, enable tools (qrencode CLI)
# Use --without-png to avoid linking issues with libpng
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static --with-tools --without-png

# Build qrencode (library and CLI tool)
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc qrencode && \
    mv qrencode.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
