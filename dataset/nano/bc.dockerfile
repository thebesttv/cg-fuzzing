FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract nano 8.7

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: nano" > /work/proj && \
    echo "version: 8.7" >> /work/proj && \
    echo "source: https://www.nano-editor.org/dist/v8/nano-8.7.tar.xz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.nano-editor.org/dist/v8/nano-8.7.tar.xz && \
    tar -xf nano-8.7.tar.xz && \
    mv nano-8.7 build && \
    rm nano-8.7.tar.xz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, ncurses for nano)
RUN apt-get update && \
    apt-get install -y file libncurses-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build nano
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    for bin in src/nano; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" /work/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la /work/bc/
