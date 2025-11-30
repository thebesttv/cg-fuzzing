FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract fribidi v1.0.15
WORKDIR /home/SVF-tools
RUN wget https://github.com/fribidi/fribidi/releases/download/v1.0.15/fribidi-1.0.15.tar.xz && \
    tar -xf fribidi-1.0.15.tar.xz && \
    rm fribidi-1.0.15.tar.xz

WORKDIR /home/SVF-tools/fribidi-1.0.15

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc bin/fribidi && \
    mv bin/fribidi.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
