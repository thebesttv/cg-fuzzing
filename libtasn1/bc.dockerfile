FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libtasn1 4.20.0
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/libtasn1/libtasn1-4.20.0.tar.gz && \
    tar -xzf libtasn1-4.20.0.tar.gz && \
    rm libtasn1-4.20.0.tar.gz

WORKDIR /home/SVF-tools/libtasn1-4.20.0

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build libtasn1
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
# libtasn1 provides: asn1Parser, asn1Coding, asn1Decoding
RUN mkdir -p ~/bc && \
    extract-bc src/asn1Parser && \
    extract-bc src/asn1Decoding && \
    mv src/asn1Parser.bc ~/bc/ && \
    mv src/asn1Decoding.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
