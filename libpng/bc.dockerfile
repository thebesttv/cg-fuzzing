FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libpng 1.6.47 (stable release)
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://download.sourceforge.net/libpng/libpng-1.6.47.tar.gz && \
    tar -xzf libpng-1.6.47.tar.gz && \
    rm libpng-1.6.47.tar.gz

WORKDIR /home/SVF-tools/libpng-1.6.47

# Install build dependencies (file for extract-bc, zlib for libpng)
RUN apt-get update && \
    apt-get install -y file zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build libpng
RUN make -j$(nproc)

# Build png2pnm (the CLI tool for fuzzing)
WORKDIR /home/SVF-tools/libpng-1.6.47/contrib/pngminus
RUN wllvm -g -O0 -I../.. -L../../.libs png2pnm.c -o png2pnm -lpng16 -lz -lm \
    -static -Wl,--allow-multiple-definition

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc png2pnm && \
    mv png2pnm.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
