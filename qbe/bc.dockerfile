FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract qbe (latest release)
WORKDIR /home/SVF-tools
RUN wget https://c9x.me/compile/release/qbe-1.2.tar.xz && \
    tar -xJf qbe-1.2.tar.xz && \
    rm qbe-1.2.tar.xz

WORKDIR /home/SVF-tools/qbe-1.2

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with WLLVM - qbe uses simple Makefile
# Need to properly override CC in Makefile context
RUN make CC=wllvm CFLAGS="-std=c99 -g -O0" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc qbe && \
    mv qbe.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
