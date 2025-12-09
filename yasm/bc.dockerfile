FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract yasm 1.3.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/yasm/yasm/releases/download/v1.3.0/yasm-1.3.0.tar.gz && \
    tar -xzf yasm-1.3.0.tar.gz && \
    rm yasm-1.3.0.tar.gz

WORKDIR /home/SVF-tools/yasm-1.3.0

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build yasm
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc yasm && \
    mv yasm.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
