FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract file 5.46
WORKDIR /home/SVF-tools
RUN wget https://astron.com/pub/file/file-5.46.tar.gz && \
    tar -xzf file-5.46.tar.gz && \
    rm file-5.46.tar.gz

WORKDIR /home/SVF-tools/file-5.46

# Install build dependencies (file for extract-bc, zlib for compression support)
RUN apt-get update && \
    apt-get install -y file zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build file
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/file && \
    mv src/file.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
