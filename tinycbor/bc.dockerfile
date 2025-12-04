FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tinycbor v0.6.1
WORKDIR /home/SVF-tools
RUN wget https://github.com/intel/tinycbor/archive/refs/tags/v0.6.1.tar.gz && \
    tar -xzf v0.6.1.tar.gz && \
    rm v0.6.1.tar.gz

WORKDIR /home/SVF-tools/tinycbor-0.6.1

# Build tinycbor with WLLVM and static linking
# Using make with CC=wllvm
RUN make CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    BUILD_SHARED=0 \
    BUILD_STATIC=1 \
    -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc bin/cbordump && \
    mv bin/cbordump.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
