FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libsodium v1.0.20

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: libsodium" > /work/proj && \
    echo "version: 1.0.20" >> /work/proj && \
    echo "source: https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz && \
    tar -xzf libsodium-1.0.20.tar.gz && \
    mv libsodium-1.0.20 build && \
    rm libsodium-1.0.20.tar.gz

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
    ./configure --disable-shared --enable-static

# Build libsodium and tests
RUN make -j$(nproc) && \
    make check -j$(nproc)

# Create bc directory and extract bitcode files from test executables
RUN mkdir -p /work/bc && \
    for bin in test/default/*; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" /work/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la /work/bc/
