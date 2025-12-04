FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract dosfstools 4.2
WORKDIR /home/SVF-tools
RUN wget https://github.com/dosfstools/dosfstools/releases/download/v4.2/dosfstools-4.2.tar.gz && \
    tar -xzf dosfstools-4.2.tar.gz && \
    rm dosfstools-4.2.tar.gz

WORKDIR /home/SVF-tools/dosfstools-4.2

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build dosfstools
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/fsck.fat && \
    mv src/fsck.fat.bc ~/bc/ && \
    extract-bc src/mkfs.fat && \
    mv src/mkfs.fat.bc ~/bc/ && \
    extract-bc src/fatlabel && \
    mv src/fatlabel.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
