FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract zziplib v0.13.80

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: zziplib" > /work/proj && \
    echo "version: 0.13.80" >> /work/proj && \
    echo "source: https://github.com/gdraheim/zziplib/archive/refs/tags/v0.13.80.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/gdraheim/zziplib/archive/refs/tags/v0.13.80.tar.gz && \
    tar -xzf v0.13.80.tar.gz && \
    mv v0.13.80 build && \
    rm v0.13.80.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, cmake for building, zlib for compression)
RUN apt-get update && \
    apt-get install -y file cmake zlib1g-dev python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build static zlib since Ubuntu doesn't provide libz.a
RUN cd /tmp && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.zlib.net/zlib-1.3.1.tar.gz && \
    tar -xzf zlib-1.3.1.tar.gz && \
    cd zlib-1.3.1 && \
    ./configure --static && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/zlib-1.3.1*

# Build zziplib with WLLVM using CMake
RUN mkdir build && cd build && \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_STATIC_LIBS=ON

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    for bin in build/bins/unzip-mem build/bins/zzcat build/bins/zzdir build/bins/zziptest build/bins/zzxorcat build/bins/zzxorcopy; do \
        if [ -f "$bin" ] && [ -x "$bin" ]; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" /work/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la /work/bc/
