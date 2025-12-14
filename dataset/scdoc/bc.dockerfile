FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract scdoc 1.11.3
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://git.sr.ht/~sircmpwn/scdoc/archive/1.11.3.tar.gz && \
    tar -xzf 1.11.3.tar.gz && \
    rm 1.11.3.tar.gz

WORKDIR /home/SVF-tools/scdoc-1.11.3

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build scdoc with WLLVM (uses simple Makefile)
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc scdoc && \
    mv scdoc.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
