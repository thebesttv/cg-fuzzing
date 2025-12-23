FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract argon2 20190702

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: argon2" > /work/proj && \
    echo "version: 20190702" >> /work/proj && \
    echo "source: https://github.com/P-H-C/phc-winner-argon2/archive/refs/tags/20190702.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/P-H-C/phc-winner-argon2/archive/refs/tags/20190702.tar.gz && \
    tar -xzf 20190702.tar.gz && \
    mv 20190702 build && \
    rm 20190702.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build argon2 with WLLVM - only build the CLI binary, not shared library
# The shared library build fails with static linking
RUN make CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes -pthread -Iinclude -Isrc" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -pthread" \
    argon2 \
    -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc argon2 && \
    mv argon2.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
