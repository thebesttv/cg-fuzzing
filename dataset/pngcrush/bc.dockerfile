FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract pngcrush v1.8.13
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://sourceforge.net/projects/pmt/files/pngcrush/1.8.13/pngcrush-1.8.13.tar.gz/download -O pngcrush-1.8.13.tar.gz && \
    tar -xzf pngcrush-1.8.13.tar.gz && \
    rm pngcrush-1.8.13.tar.gz

WORKDIR /home/SVF-tools/pngcrush-1.8.13

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file libz-dev libpng-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with WLLVM (static linking)
# pngcrush Makefile hardcodes CC=gcc, so we need to override it explicitly
RUN make CC=wllvm \
    LD=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc pngcrush && \
    mv pngcrush.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
