FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract zlib 1.3.1
WORKDIR /home/SVF-tools
RUN wget https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz && \
    tar -xzf zlib-1.3.1.tar.gz && \
    rm zlib-1.3.1.tar.gz

WORKDIR /home/SVF-tools/zlib-1.3.1

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --static

# Build zlib and minigzip
RUN make -j$(nproc)

# Build minigzip (the CLI tool for fuzzing)
RUN make -j$(nproc) minigzip

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc minigzip && \
    mv minigzip.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
