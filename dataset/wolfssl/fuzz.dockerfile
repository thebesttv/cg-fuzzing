FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract wolfssl 5.7.4 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.4-stable.tar.gz && \
    tar -xzf v5.7.4-stable.tar.gz && \
    rm v5.7.4-stable.tar.gz

WORKDIR /src/wolfssl-5.7.4-stable

# Generate configure script
RUN ./autogen.sh

# Build wolfssl with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --enable-crypttests

RUN make -j$(nproc)

RUN cp examples/asn1/asn1 /out/asn1

# Build CMPLOG version
WORKDIR /src
RUN rm -rf wolfssl-5.7.4-stable && \
    wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.4-stable.tar.gz && \
    tar -xzf v5.7.4-stable.tar.gz && \
    rm v5.7.4-stable.tar.gz

WORKDIR /src/wolfssl-5.7.4-stable

RUN ./autogen.sh

RUN AFL_LLVM_CMPLOG=1 CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --enable-crypttests

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN cp examples/asn1/asn1 /out/asn1.cmplog

# Copy fuzzing resources
COPY wolfssl/fuzz/dict /out/dict
COPY wolfssl/fuzz/in /out/in
COPY wolfssl/fuzz/fuzz.sh /out/fuzz.sh
COPY wolfssl/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/asn1 /out/asn1.cmplog && \
    file /out/asn1

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing wolfssl'"]
