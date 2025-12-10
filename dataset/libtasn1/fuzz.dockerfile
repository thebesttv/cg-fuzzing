FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libtasn1 4.20.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://ftp.gnu.org/gnu/libtasn1/libtasn1-4.20.0.tar.gz && \
    tar -xzf libtasn1-4.20.0.tar.gz && \
    rm libtasn1-4.20.0.tar.gz

WORKDIR /src/libtasn1-4.20.0

# Build libtasn1 with afl-clang-lto for fuzzing (main target binary)
# Use static linking for better reproducibility
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the asn1Parser binary (parses ASN.1 definition files)
RUN cp src/asn1Parser /out/asn1Parser

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libtasn1-4.20.0 && \
    wget https://ftp.gnu.org/gnu/libtasn1/libtasn1-4.20.0.tar.gz && \
    tar -xzf libtasn1-4.20.0.tar.gz && \
    rm libtasn1-4.20.0.tar.gz

WORKDIR /src/libtasn1-4.20.0

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/asn1Parser /out/asn1Parser.cmplog

# Copy fuzzing resources
COPY dataset/libtasn1/fuzz/dict /out/dict
COPY dataset/libtasn1/fuzz/in /out/in
COPY dataset/libtasn1/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libtasn1/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/asn1Parser /out/asn1Parser.cmplog && \
    file /out/asn1Parser

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libtasn1'"]
