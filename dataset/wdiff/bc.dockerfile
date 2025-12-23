FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract wdiff 1.2.2

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: wdiff" > /work/proj && \
    echo "version: 1.2.2" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/wdiff/wdiff-1.2.2.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/wdiff/wdiff-1.2.2.tar.gz && \
    tar -xzf wdiff-1.2.2.tar.gz && \
    mv wdiff-1.2.2 build && \
    rm wdiff-1.2.2.tar.gz

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
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build wdiff (skip doc directory which requires makeinfo)
RUN make -C lib -j$(nproc) && \
    make -C po -j$(nproc) && \
    make -C src -j$(nproc)

# Create bc directory and extract bitcode files
# wdiff produces: wdiff, mdiff (for comparing multiple files)
RUN mkdir -p /work/bc && \
    extract-bc src/wdiff && \
    mv src/wdiff.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
