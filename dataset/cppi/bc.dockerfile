FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract cppi v1.18

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: cppi" > /work/proj && \
    echo "version: 1.18" >> /work/proj && \
    echo "source: https://mirror.keystealth.org/gnu/cppi/cppi-1.18.tar.xz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 --no-check-certificate https://mirror.keystealth.org/gnu/cppi/cppi-1.18.tar.xz && \
    tar -xf cppi-1.18.tar.xz && \
    mv cppi-1.18 build && \
    rm cppi-1.18.tar.xz

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

# Build cppi
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/cppi && \
    mv src/cppi.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
