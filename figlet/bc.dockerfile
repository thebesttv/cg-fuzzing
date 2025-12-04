FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract figlet v2.2.5
WORKDIR /home/SVF-tools
RUN wget https://github.com/cmatsuoka/figlet/archive/refs/tags/2.2.5.tar.gz -O figlet-2.2.5.tar.gz && \
    tar -xzf figlet-2.2.5.tar.gz && \
    rm figlet-2.2.5.tar.gz

WORKDIR /home/SVF-tools/figlet-2.2.5

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build figlet with WLLVM (Makefile-based project)
RUN make CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc figlet && \
    mv figlet.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
