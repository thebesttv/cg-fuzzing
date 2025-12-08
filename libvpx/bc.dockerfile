FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libvpx v1.14.1
WORKDIR /home/SVF-tools
RUN wget https://github.com/webmproject/libvpx/archive/refs/tags/v1.14.1.tar.gz && \
    tar -xzf v1.14.1.tar.gz && \
    rm v1.14.1.tar.gz

WORKDIR /home/SVF-tools/libvpx-1.14.1

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
RUN mkdir -p ~/bc && \
    if [ -f "vpxdec" ] && [ -x "vpxdec" ]; then \
        extract-bc vpxdec && \
        mv vpxdec.bc ~/bc/; \
    fi

# Verify that bc files were created
RUN ls -la ~/bc/
