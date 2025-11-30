FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lzo 2.10
WORKDIR /home/SVF-tools
RUN wget https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz && \
    tar -xzf lzo-2.10.tar.gz && \
    rm lzo-2.10.tar.gz

WORKDIR /home/SVF-tools/lzo-2.10

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build lzo
RUN make -j$(nproc)

# Build lzopack example manually - need to add include paths properly
RUN cd examples && \
    wllvm -g -O0 -I. -I../include -I.. -static -Wl,--allow-multiple-definition \
        -o lzopack lzopack.c ../src/.libs/liblzo2.a

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc examples/lzopack && \
    mv examples/lzopack.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
