FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract antiword (latest main branch)
WORKDIR /home/SVF-tools
RUN wget https://github.com/grobian/antiword/archive/refs/heads/main.tar.gz -O antiword.tar.gz && \
    tar -xzf antiword.tar.gz && \
    rm antiword.tar.gz

WORKDIR /home/SVF-tools/antiword-main

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build antiword with WLLVM (Makefile-based project)
# antiword uses a simple Makefile
RUN make CC=wllvm \
    CFLAGS="-g -O0 -DNDEBUG" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc antiword && \
    mv antiword.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
