FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libarchive 3.8.3
WORKDIR /home/SVF-tools
RUN wget https://github.com/libarchive/libarchive/releases/download/v3.8.3/libarchive-3.8.3.tar.gz && \
    tar -xzf libarchive-3.8.3.tar.gz && \
    rm libarchive-3.8.3.tar.gz

WORKDIR /home/SVF-tools/libarchive-3.8.3

# Install build dependencies (file for extract-bc, plus compression libraries)
RUN apt-get update && \
    apt-get install -y file liblzma-dev libbz2-dev zlib1g-dev libzstd-dev liblz4-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure and build with WLLVM (using autotools)
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static \
    --without-xml2 --without-expat --without-openssl \
    --enable-bsdtar=static --enable-bsdcpio=static

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
# bsdtar is the main CLI binary
RUN mkdir -p ~/bc && \
    extract-bc bsdtar && \
    mv bsdtar.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
