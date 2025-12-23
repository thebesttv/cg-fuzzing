FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract dash v0.5.12

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: dash" > /work/proj && \
    echo "version: 0.5.12" >> /work/proj && \
    echo "source: http://gondor.apana.org.au/~herbert/dash/files/dash-0.5.12.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 http://gondor.apana.org.au/~herbert/dash/files/dash-0.5.12.tar.gz && \
    tar -xzf dash-0.5.12.tar.gz && \
    mv dash-0.5.12 build && \
    rm dash-0.5.12.tar.gz

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
    ./configure

# Build dash
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/dash && \
    mv src/dash.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
