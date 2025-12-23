FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libconfuse v3.3 (official tarball with configure)

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: libconfuse" > /work/proj && \
    echo "version: 3.3" >> /work/proj && \
    echo "source: https://github.com/libconfuse/libconfuse/releases/download/v3.3/confuse-3.3.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget https://github.com/libconfuse/libconfuse/releases/download/v3.3/confuse-3.3.tar.gz && \
    tar -xzf confuse-3.3.tar.gz && \
    mv confuse-3.3 build && \
    rm confuse-3.3.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, flex for building)
RUN apt-get update && \
    apt-get install -y file flex && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build libconfuse
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from examples
RUN mkdir -p /work/bc && \
    for bin in examples/*; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" /work/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la /work/bc/
