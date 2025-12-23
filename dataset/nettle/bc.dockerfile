FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract nettle 3.10.2

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: nettle" > /work/proj && \
    echo "version: 3.10.2" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/nettle/nettle-3.10.2.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/nettle/nettle-3.10.2.tar.gz && \
    tar -xzf nettle-3.10.2.tar.gz && \
    mv nettle-3.10.2 build && \
    rm nettle-3.10.2.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libgmp-dev m4 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Note: nettle needs special handling for static linking
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --disable-openssl --enable-static

# Build nettle
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
# nettle provides: sexp-conv (S-expression converter), nettle-hash (hash computation)
RUN mkdir -p /work/bc && \
    extract-bc tools/sexp-conv && \
    extract-bc tools/nettle-hash && \
    mv tools/sexp-conv.bc /work/bc/ && \
    mv tools/nettle-hash.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
