FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract catdoc 0.95 (same version as bc.dockerfile)
WORKDIR /src
RUN wget "http://ftp.wagner.pp.ru/pub/catdoc/catdoc-0.95.tar.gz" && \
    tar -xzf catdoc-0.95.tar.gz && \
    rm catdoc-0.95.tar.gz

WORKDIR /src/catdoc-0.95

# Configure and build catdoc with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make CC=afl-clang-lto LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Install the catdoc binary
RUN cp src/catdoc /out/catdoc

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf catdoc-0.95 && \
    wget "http://ftp.wagner.pp.ru/pub/catdoc/catdoc-0.95.tar.gz" && \
    tar -xzf catdoc-0.95.tar.gz && \
    rm catdoc-0.95.tar.gz

WORKDIR /src/catdoc-0.95

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Install CMPLOG binary
RUN cp src/catdoc /out/catdoc.cmplog

# Copy fuzzing resources
COPY catdoc/fuzz/dict /out/dict
COPY catdoc/fuzz/in /out/in
COPY catdoc/fuzz/fuzz.sh /out/fuzz.sh
COPY catdoc/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/catdoc /out/catdoc.cmplog && \
    file /out/catdoc && \
    /out/catdoc -V || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing catdoc'"]
