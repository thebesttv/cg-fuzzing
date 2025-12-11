FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract discount v3.0.1.2
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Orc/discount/archive/refs/tags/v3.0.1.2.tar.gz && \
    tar -xzf v3.0.1.2.tar.gz && \
    rm v3.0.1.2.tar.gz

WORKDIR /home/SVF-tools/discount-3.0.1.2

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure and build discount with WLLVM
# discount uses its own configure script
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure.sh

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc markdown && \
    mv markdown.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
