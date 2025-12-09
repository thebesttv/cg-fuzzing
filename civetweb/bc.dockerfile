FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract civetweb v1.16
WORKDIR /home/SVF-tools
RUN wget https://github.com/civetweb/civetweb/archive/refs/tags/v1.16.tar.gz && \
    tar -xzf v1.16.tar.gz && \
    rm v1.16.tar.gz

WORKDIR /home/SVF-tools/civetweb-1.16

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build civetweb with WLLVM
# Build main library and server
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make WITH_ALL=1 lib

# Build the server binary
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make WITH_ALL=1

# Create bc directory and extract bitcode
RUN mkdir -p ~/bc && \
    extract-bc civetweb && \
    mv civetweb.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
