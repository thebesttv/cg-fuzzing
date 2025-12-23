FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lame v3.100

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: lame" > /work/proj && \
    echo "version: 3.100" >> /work/proj && \
    echo "source: https://downloads.sourceforge.net/lame/lame-3.100.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://downloads.sourceforge.net/lame/lame-3.100.tar.gz && \
    tar -xzf lame-3.100.tar.gz && \
    mv lame-3.100 build && \
    rm lame-3.100.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build lame
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc frontend/lame && \
    mv frontend/lame.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
