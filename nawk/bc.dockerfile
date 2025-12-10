FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract nawk (one true awk) 20240728
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/onetrueawk/awk/archive/refs/tags/20240728.tar.gz -O nawk.tar.gz && \
    tar -xzf nawk.tar.gz && \
    rm nawk.tar.gz

WORKDIR /home/SVF-tools/awk-20240728

# Build with WLLVM
# nawk uses a simple Makefile - override CC and HOSTCC
RUN make CC=wllvm HOSTCC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc a.out && \
    mv a.out.bc ~/bc/nawk.bc

# Verify that bc files were created
RUN ls -la ~/bc/
