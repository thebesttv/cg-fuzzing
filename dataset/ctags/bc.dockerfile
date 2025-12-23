FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract ctags v6.2.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: ctags" > /work/proj && \
    echo "version: 6.2.1" >> /work/proj && \
    echo "source: https://github.com/universal-ctags/ctags/releases/download/v6.2.1/universal-ctags-6.2.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/universal-ctags/ctags/releases/download/v6.2.1/universal-ctags-6.2.1.tar.gz && \
    tar -xzf universal-ctags-6.2.1.tar.gz && \
    mv universal-ctags-6.2.1 build && \
    rm universal-ctags-6.2.1.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, autoconf etc for build)
RUN apt-get update && \
    apt-get install -y file autoconf automake pkg-config libyaml-dev libjansson-dev libseccomp-dev libpcre2-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Disable optional features to simplify static linking
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure \
        --disable-shared \
        --disable-xml \
        --disable-json \
        --disable-yaml \
        --disable-seccomp \
        --disable-pcre2

# Build ctags
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc ctags && \
    mv ctags.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
