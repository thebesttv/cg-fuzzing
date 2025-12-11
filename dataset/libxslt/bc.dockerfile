FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libxslt v1.1.42
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.gnome.org/sources/libxslt/1.1/libxslt-1.1.42.tar.xz && \
    tar -xf libxslt-1.1.42.tar.xz && \
    rm libxslt-1.1.42.tar.xz

WORKDIR /home/SVF-tools/libxslt-1.1.42

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libxml2-dev xz-utils liblzma-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --without-python --without-crypto

# Build libxslt
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from xsltproc binary
RUN mkdir -p ~/bc && \
    extract-bc xsltproc/xsltproc && \
    mv xsltproc/xsltproc.bc ~/bc/ 2>/dev/null || true

# Verify that bc files were created
RUN ls -la ~/bc/
