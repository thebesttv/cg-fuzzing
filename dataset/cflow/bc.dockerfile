FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract cflow v1.7

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: cflow" > /work/proj && \
    echo "version: 1.7" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/cflow/cflow-1.7.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/cflow/cflow-1.7.tar.gz && \
    tar -xzf cflow-1.7.tar.gz && \
    mv cflow-1.7 build && \
    rm cflow-1.7.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-nls

# Build cflow
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/cflow && \
    mv src/cflow.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
