FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libfyaml v0.9
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/pantoniou/libfyaml/releases/download/v0.9/libfyaml-0.9.tar.gz && \
    tar -xzf libfyaml-0.9.tar.gz && \
    rm libfyaml-0.9.tar.gz

WORKDIR /home/SVF-tools/libfyaml-0.9

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build libfyaml
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from fy-tool
RUN mkdir -p ~/bc && \
    extract-bc src/fy-tool && \
    mv src/fy-tool.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
