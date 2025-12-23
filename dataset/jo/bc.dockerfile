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

# Download and extract jo 1.9

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: jo" > /work/proj && \
    echo "version: 1.9" >> /work/proj && \
    echo "source: https://github.com/jpmens/jo/releases/download/1.9/jo-1.9.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jpmens/jo/releases/download/1.9/jo-1.9.tar.gz && \
    tar -xzf jo-1.9.tar.gz && \
    mv jo-1.9 build && \
    rm jo-1.9.tar.gz

WORKDIR /work/build

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build jo
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc jo && \
    mv jo.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
