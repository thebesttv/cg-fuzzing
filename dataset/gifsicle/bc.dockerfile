FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract gifsicle v1.96

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: gifsicle" > /work/proj && \
    echo "version: 1.96" >> /work/proj && \
    echo "source: https://www.lcdf.org/gifsicle/gifsicle-1.96.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.lcdf.org/gifsicle/gifsicle-1.96.tar.gz && \
    tar -xzf gifsicle-1.96.tar.gz && \
    mv gifsicle-1.96 build && \
    rm gifsicle-1.96.tar.gz

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
    ./configure --disable-shared

# Build gifsicle
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/gifsicle && \
    mv src/gifsicle.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
