FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract pigz v2.8
WORKDIR /home/SVF-tools
RUN wget https://github.com/madler/pigz/archive/refs/tags/v2.8.tar.gz && \
    tar -xzf v2.8.tar.gz && \
    rm v2.8.tar.gz

WORKDIR /home/SVF-tools/pigz-2.8

# Build pigz with WLLVM
# pigz uses a simple Makefile
RUN make clean || true && \
    make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc pigz && \
    mv pigz.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
