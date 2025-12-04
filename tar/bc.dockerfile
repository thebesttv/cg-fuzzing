FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tar v1.35
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/tar/tar-1.35.tar.xz && \
    tar -xJf tar-1.35.tar.xz && \
    rm tar-1.35.tar.xz

WORKDIR /home/SVF-tools/tar-1.35

# Install build dependencies (file for extract-bc, xz for extraction)
RUN apt-get update && \
    apt-get install -y file xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build tar
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/tar && \
    mv src/tar.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
