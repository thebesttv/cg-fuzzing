FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libplist 2.7.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: libplist" > /work/proj && \
    echo "version: 2.7.0" >> /work/proj && \
    echo "source: https://github.com/libimobiledevice/libplist/archive/refs/tags/2.7.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libimobiledevice/libplist/archive/refs/tags/2.7.0.tar.gz && \
    tar -xzf 2.7.0.tar.gz && \
    mv 2.7.0 build && \
    rm 2.7.0.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create version file (needed when building from tarball)
RUN echo "2.7.0" > .tarball-version

# Bootstrap the project (generate configure script)
RUN NOCONFIGURE=1 ./autogen.sh

# Configure with static linking and WLLVM
# Disable Cython bindings as we only need the C library and CLI tool
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --without-cython

# Add static flags to the Makefile for linking
RUN find . -name Makefile -exec sed -i 's/\(plistutil_LDADD = \)/\1-all-static /' {} \;

# Build libplist
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc tools/plistutil && \
    mv tools/plistutil.bc /work/bc/

# Verify that bc files were created and binary is static
RUN ls -la /work/bc/ && \
    file tools/plistutil && \
    ldd tools/plistutil 2>&1 || echo "Binary is statically linked"
