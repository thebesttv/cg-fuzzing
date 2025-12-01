FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libplist 2.7.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/libimobiledevice/libplist/archive/refs/tags/2.7.0.tar.gz && \
    tar -xzf 2.7.0.tar.gz && \
    rm 2.7.0.tar.gz

WORKDIR /home/SVF-tools/libplist-2.7.0

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
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --without-cython

# Add static flags to the Makefile for linking
RUN find . -name Makefile -exec sed -i 's/\(plistutil_LDADD = \)/\1-all-static /' {} \;

# Build libplist
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc tools/plistutil && \
    mv tools/plistutil.bc ~/bc/

# Verify that bc files were created and binary is static
RUN ls -la ~/bc/ && \
    file tools/plistutil && \
    ldd tools/plistutil 2>&1 || echo "Binary is statically linked"
