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

# Download and extract opus v1.5.2

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: opus" > /work/proj && \
    echo "version: 1.5.2" >> /work/proj && \
    echo "source: https://github.com/xiph/opus/releases/download/v1.5.2/opus-1.5.2.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/opus/releases/download/v1.5.2/opus-1.5.2.tar.gz && \
    tar -xzf opus-1.5.2.tar.gz && \
    mv opus-1.5.2 build && \
    rm opus-1.5.2.tar.gz

WORKDIR /work/build

# Configure with static linking and WLLVM
# Enable all optional features for better fuzzing coverage
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-doc

# Build opus library and demo tools
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc opus_demo && \
    mv opus_demo.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
