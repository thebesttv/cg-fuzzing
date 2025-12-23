FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract curl v8.17.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: curl" > /work/proj && \
    echo "version: 8.17.0" >> /work/proj && \
    echo "source: https://github.com/curl/curl/releases/download/curl-8_17_0/curl-8.17.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/curl/curl/releases/download/curl-8_17_0/curl-8.17.0.tar.gz && \
    tar -xzf curl-8.17.0.tar.gz && \
    mv curl-8.17.0 build && \
    rm curl-8.17.0.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, ssl for https support)
RUN apt-get update && \
    apt-get install -y file libssl-dev zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Disable shared libraries and enable static curl
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --with-openssl --without-libpsl

# Build curl
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/curl && \
    mv src/curl.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
