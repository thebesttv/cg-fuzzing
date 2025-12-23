FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lrzip v0.651

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: lrzip" > /work/proj && \
    echo "version: 0.651" >> /work/proj && \
    echo "source: https://github.com/ckolivas/lrzip/archive/refs/tags/v0.651.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ckolivas/lrzip/archive/refs/tags/v0.651.tar.gz && \
    tar -xzf v0.651.tar.gz && \
    mv v0.651 build && \
    rm v0.651.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool libbz2-dev liblzo2-dev zlib1g-dev liblz4-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Generate configure script
RUN ./autogen.sh

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static

# Build lrzip
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc lrzip && \
    mv lrzip.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
