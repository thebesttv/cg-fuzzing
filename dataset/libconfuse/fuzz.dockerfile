FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget flex && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libconfuse v3.3 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/libconfuse/libconfuse/releases/download/v3.3/confuse-3.3.tar.gz && \
    tar -xzf confuse-3.3.tar.gz && \
    rm confuse-3.3.tar.gz

WORKDIR /src/confuse-3.3

# Build libconfuse with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)
RUN cp examples/simple /out/simple

# Build CMPLOG version
WORKDIR /src
RUN rm -rf confuse-3.3 && \
    wget https://github.com/libconfuse/libconfuse/releases/download/v3.3/confuse-3.3.tar.gz && \
    tar -xzf confuse-3.3.tar.gz && \
    rm confuse-3.3.tar.gz

WORKDIR /src/confuse-3.3

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp examples/simple /out/simple.cmplog

# Copy fuzzing resources
COPY libconfuse/fuzz/dict /out/dict
COPY libconfuse/fuzz/in /out/in
COPY libconfuse/fuzz/fuzz.sh /out/fuzz.sh
COPY libconfuse/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/simple /out/simple.cmplog && \
    file /out/simple

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libconfuse'"]
