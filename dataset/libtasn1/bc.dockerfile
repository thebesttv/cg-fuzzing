FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libtasn1 4.20.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: libtasn1" > /work/proj && \
    echo "version: 4.20.0" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/libtasn1/libtasn1-4.20.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/libtasn1/libtasn1-4.20.0.tar.gz && \
    tar -xzf libtasn1-4.20.0.tar.gz && \
    mv libtasn1-4.20.0 build && \
    rm libtasn1-4.20.0.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build libtasn1
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
# libtasn1 provides: asn1Parser, asn1Coding, asn1Decoding
RUN mkdir -p /work/bc && \
    extract-bc src/asn1Parser && \
    extract-bc src/asn1Decoding && \
    mv src/asn1Parser.bc /work/bc/ && \
    mv src/asn1Decoding.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
