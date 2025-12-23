FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract catdoc 0.95

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: catdoc" > /work/proj && \
    echo "version: 0.95" >> /work/proj && \
    echo "source: http://ftp.wagner.pp.ru/pub/catdoc/catdoc-0.95.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget "http://ftp.wagner.pp.ru/pub/catdoc/catdoc-0.95.tar.gz" && \
    tar -xzf catdoc-0.95.tar.gz && \
    mv catdoc-0.95 build && \
    rm catdoc-0.95.tar.gz

WORKDIR /work/build

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build catdoc
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/catdoc && \
    mv src/catdoc.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
