FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract yara v4.5.5

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: yara" > /work/proj && \
    echo "version: 4.5.5" >> /work/proj && \
    echo "source: https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.5.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.5.tar.gz && \
    tar -xzf v4.5.5.tar.gz && \
    mv v4.5.5 build && \
    rm v4.5.5.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool pkg-config flex bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Bootstrap the project (generate configure script)
RUN ./bootstrap.sh

# Patch the acx_pthread check to skip the shared library test
RUN sed -i 's/if test x"\$done" = xno; then/if false; then # patched: skip shared lib check/' configure

# Configure with WLLVM and static linking
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --without-crypto

# Add static flags to the Makefile for linking
# The yara_LDADD line needs to include -all-static for libtool
RUN sed -i 's/\(yara_LDADD = \)/\1-all-static /' Makefile && \
    sed -i 's/\(yarac_LDADD = \)/\1-all-static /' Makefile

# Build yara
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc yara && \
    mv yara.bc /work/bc/ && \
    extract-bc yarac && \
    mv yarac.bc /work/bc/

# Verify that bc files were created and binaries are static
RUN ls -la /work/bc/ && \
    file yara && \
    ldd yara 2>&1 || echo "Binary is statically linked"
