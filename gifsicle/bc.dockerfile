FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract gifsicle v1.96
WORKDIR /home/SVF-tools
RUN wget https://www.lcdf.org/gifsicle/gifsicle-1.96.tar.gz && \
    tar -xzf gifsicle-1.96.tar.gz && \
    rm gifsicle-1.96.tar.gz

WORKDIR /home/SVF-tools/gifsicle-1.96

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

# Build gifsicle
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/gifsicle && \
    mv src/gifsicle.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
