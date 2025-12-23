FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract giflib 5.2.2

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: giflib" > /work/proj && \
    echo "version: 5.2.2" >> /work/proj && \
    echo "source: https://sourceforge.net/projects/giflib/files/giflib-5.2.2.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://sourceforge.net/projects/giflib/files/giflib-5.2.2.tar.gz && \
    tar -xzf giflib-5.2.2.tar.gz && \
    mv giflib-5.2.2 build && \
    rm giflib-5.2.2.tar.gz

WORKDIR /work/build

# Build with WLLVM for bitcode extraction
# giflib uses a simple Makefile - build only static library and tools
RUN make clean 2>/dev/null || true && \
    make CC=wllvm \
    CFLAGS="-std=gnu99 -Wall -g -O0 -Xclang -disable-llvm-passes" \
    libgif.a

# Build the tools statically
RUN make CC=wllvm \
    CFLAGS="-std=gnu99 -Wall -g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    gif2rgb gifbuild giftool giftext gifclrmp giffix

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    for bin in giftext gif2rgb gifbuild giftool gifclrmp giffix; do \
        if [ -f "$bin" ] && [ -x "$bin" ]; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" /work/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la /work/bc/
