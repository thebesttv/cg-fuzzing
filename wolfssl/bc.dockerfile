FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract wolfssl 5.7.4
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.4-stable.tar.gz && \
    tar -xzf v5.7.4-stable.tar.gz && \
    rm v5.7.4-stable.tar.gz

WORKDIR /home/SVF-tools/wolfssl-5.7.4-stable

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Generate configure script
RUN ./autogen.sh

# Configure with static linking and WLLVM
# Enable wolfcrypt test tool for bitcode extraction
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static --enable-crypttests

# Build wolfssl
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
# wolfssl provides asn1 tool for parsing ASN.1/DER files
RUN mkdir -p ~/bc && \
    extract-bc examples/asn1/asn1 && \
    mv examples/asn1/asn1.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
