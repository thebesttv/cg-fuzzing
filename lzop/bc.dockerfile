FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lzop v1.04
WORKDIR /home/SVF-tools
RUN wget https://www.lzop.org/download/lzop-1.04.tar.gz && \
    tar -xzf lzop-1.04.tar.gz && \
    rm lzop-1.04.tar.gz

# Download and build lzo library (dependency)
RUN wget https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz && \
    tar -xzf lzo-2.10.tar.gz && \
    rm lzo-2.10.tar.gz

WORKDIR /home/SVF-tools/lzo-2.10

# Build lzo library with wllvm
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)
RUN make install

# Build lzop
WORKDIR /home/SVF-tools/lzop-1.04

RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-asm

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/lzop && \
    mv src/lzop.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
