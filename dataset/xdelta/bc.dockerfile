FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract xdelta v3.1.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: xdelta" > /work/proj && \
    echo "version: 3.1.0" >> /work/proj && \
    echo "source: https://github.com/jmacd/xdelta/archive/refs/tags/v3.1.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jmacd/xdelta/archive/refs/tags/v3.1.0.tar.gz && \
    tar -xzf v3.1.0.tar.gz && \
    mv v3.1.0 build && \
    rm v3.1.0.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Generate configure script
RUN autoreconf -fi

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure

# Build xdelta3
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    if [ -f "xdelta3" ] && [ -x "xdelta3" ]; then \
        extract-bc xdelta3 && \
        mv xdelta3.bc /work/bc/ 2>/dev/null || true; \
    fi

# Verify that bc files were created
RUN ls -la /work/bc/
