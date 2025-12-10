FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libssl-dev zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract curl v8.17.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/curl/curl/releases/download/curl-8_17_0/curl-8.17.0.tar.gz && \
    tar -xzf curl-8.17.0.tar.gz && \
    rm curl-8.17.0.tar.gz

WORKDIR /src/curl-8.17.0

# Build curl with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --with-openssl --without-libpsl

RUN make -j$(nproc)

# Install the curl binary
RUN cp src/curl /out/curl

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf curl-8.17.0 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/curl/curl/releases/download/curl-8_17_0/curl-8.17.0.tar.gz && \
    tar -xzf curl-8.17.0.tar.gz && \
    rm curl-8.17.0.tar.gz

WORKDIR /src/curl-8.17.0

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --with-openssl --without-libpsl

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/curl /out/curl.cmplog

# Copy fuzzing resources
COPY curl/fuzz/dict /out/dict
COPY curl/fuzz/in /out/in
COPY curl/fuzz/fuzz.sh /out/fuzz.sh
COPY curl/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/curl /out/curl.cmplog && \
    file /out/curl && \
    /out/curl --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing curl'"]
