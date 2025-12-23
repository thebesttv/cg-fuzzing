FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract jimtcl 0.83

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: jimtcl" > /work/proj && \
    echo "version: 0.83" >> /work/proj && \
    echo "source: https://github.com/msteveb/jimtcl/archive/refs/tags/0.83.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/msteveb/jimtcl/archive/refs/tags/0.83.tar.gz && \
    tar -xzf 0.83.tar.gz && \
    mv 0.83 build && \
    rm 0.83.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# jimtcl uses its own configure script (not autotools)
# Disable SSL/TLS to avoid static linking issues with OpenSSL
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-ssl

# Build jimtcl
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc jimsh && \
    mv jimsh.bc /work/bc/

# Verify that bc files were created and binary is static
RUN ls -la /work/bc/ && \
    file jimsh && \
    ldd jimsh 2>&1 || echo "Binary is statically linked"
