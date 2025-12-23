FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract hunspell v1.7.2

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: hunspell" > /work/proj && \
    echo "version: 1.7.2" >> /work/proj && \
    echo "source: https://github.com/hunspell/hunspell/releases/download/v1.7.2/hunspell-1.7.2.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/hunspell/hunspell/releases/download/v1.7.2/hunspell-1.7.2.tar.gz && \
    tar -xzf hunspell-1.7.2.tar.gz && \
    mv hunspell-1.7.2 build && \
    rm hunspell-1.7.2.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -static-libstdc++" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static

# Build hunspell
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from hunspell binary
RUN mkdir -p /work/bc && \
    extract-bc src/tools/hunspell && \
    mv src/tools/hunspell.bc /work/bc/ 2>/dev/null || true

# Verify that bc files were created
RUN ls -la /work/bc/
