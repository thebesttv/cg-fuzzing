FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract ccrypt 1.11

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: ccrypt" > /work/proj && \
    echo "version: 1.11" >> /work/proj && \
    echo "source: https://ccrypt.sourceforge.net/download/1.11/ccrypt-1.11.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ccrypt.sourceforge.net/download/1.11/ccrypt-1.11.tar.gz && \
    tar -xzf ccrypt-1.11.tar.gz && \
    mv ccrypt-1.11 build && \
    rm ccrypt-1.11.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure

# Build ccrypt
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/ccrypt && \
    mv src/ccrypt.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
