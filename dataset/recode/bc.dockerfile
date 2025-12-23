FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract recode v3.7.14

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: recode" > /work/proj && \
    echo "version: 3.7.14" >> /work/proj && \
    echo "source: https://github.com/rrthomas/recode/releases/download/v3.7.14/recode-3.7.14.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/rrthomas/recode/releases/download/v3.7.14/recode-3.7.14.tar.gz && \
    tar -xzf recode-3.7.14.tar.gz && \
    mv recode-3.7.14 build && \
    rm recode-3.7.14.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file flex bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --without-libiconv-prefix

# Build
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/recode && \
    mv src/recode.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
