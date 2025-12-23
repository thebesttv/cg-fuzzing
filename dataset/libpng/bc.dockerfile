FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libpng 1.6.47 (stable release)

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: libpng" > /work/proj && \
    echo "version: 1.6.47" >> /work/proj && \
    echo "source: https://download.sourceforge.net/libpng/libpng-1.6.47.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.sourceforge.net/libpng/libpng-1.6.47.tar.gz && \
    tar -xzf libpng-1.6.47.tar.gz && \
    mv libpng-1.6.47 build && \
    rm libpng-1.6.47.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, zlib for libpng)
RUN apt-get update && \
    apt-get install -y file zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build libpng
RUN make -j$(nproc)

# Build png2pnm (the CLI tool for fuzzing)
WORKDIR /work/build/contrib/pngminus
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -I../.. -L../../.libs png2pnm.c -o png2pnm -lpng16 -lz -lm \
    -static -Wl,--allow-multiple-definition

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc png2pnm && \
    mv png2pnm.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
