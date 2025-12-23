FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y autoconf automake libtool file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract flac v1.5.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: flac" > /work/proj && \
    echo "version: 1.5.0" >> /work/proj && \
    echo "source: https://github.com/xiph/flac/releases/download/1.5.0/flac-1.5.0.tar.xz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/flac/releases/download/1.5.0/flac-1.5.0.tar.xz && \
    tar -xJf flac-1.5.0.tar.xz && \
    mv flac-1.5.0 build && \
    rm flac-1.5.0.tar.xz

WORKDIR /work/build

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-ogg

# Build flac
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/flac/flac && \
    mv src/flac/flac.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
