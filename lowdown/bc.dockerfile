FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lowdown 1.1.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/kristapsdz/lowdown/archive/refs/tags/VERSION_1_1_0.tar.gz && \
    tar -xzf VERSION_1_1_0.tar.gz && \
    rm VERSION_1_1_0.tar.gz

WORKDIR /home/SVF-tools/lowdown-VERSION_1_1_0

# Configure lowdown (uses simple configure script)
RUN ./configure

# Build lowdown binary only (not shared library) with WLLVM and static linking
RUN make lowdown CC=wllvm CFLAGS="-g -O0" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc lowdown && \
    mv lowdown.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
