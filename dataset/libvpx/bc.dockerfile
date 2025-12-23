FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libvpx v1.14.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: libvpx" > /work/proj && \
    echo "version: 1.14.1" >> /work/proj && \
    echo "source: https://github.com/webmproject/libvpx/archive/refs/tags/v1.14.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/webmproject/libvpx/archive/refs/tags/v1.14.1.tar.gz && \
    tar -xzf v1.14.1.tar.gz && \
    mv v1.14.1 build && \
    rm v1.14.1.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file yasm && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Configure without disabling tools to build vpxdec
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --enable-static --disable-shared --enable-vp9-highbitdepth

# Build libvpx library and tools (make target: all)
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from built vpxdec
RUN mkdir -p /work/bc && \
    if [ -f "vpxdec" ] && [ -x "vpxdec" ]; then \
        extract-bc vpxdec && \
        mv vpxdec.bc /work/bc/; \
    fi

# Verify that bc files were created
RUN ls -la /work/bc/
