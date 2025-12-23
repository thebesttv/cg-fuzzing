FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract gengetopt 2.23

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: gengetopt" > /work/proj && \
    echo "version: 2.23" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/gengetopt/gengetopt-2.23.tar.xz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/gengetopt/gengetopt-2.23.tar.xz && \
    tar -xJf gengetopt-2.23.tar.xz && \
    mv gengetopt-2.23 build && \
    rm gengetopt-2.23.tar.xz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file texinfo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build gengetopt
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/gengetopt && \
    mv src/gengetopt.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
