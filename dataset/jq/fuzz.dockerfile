FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool bison flex && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract jq v1.8.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz && \
    tar -xzf jq-1.8.1.tar.gz && \
    rm jq-1.8.1.tar.gz

WORKDIR /src/jq-1.8.1

# Build jq with afl-clang-lto for fuzzing (main target binary)
# Use static linking and builtin oniguruma
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static

RUN make -j$(nproc)

# Install the jq binary
RUN cp jq /out/jq

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf jq-1.8.1 && \
    wget https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz && \
    tar -xzf jq-1.8.1.tar.gz && \
    rm jq-1.8.1.tar.gz

WORKDIR /src/jq-1.8.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp jq /out/jq.cmplog

# Copy fuzzing resources
COPY jq/fuzz/dict /out/dict
COPY jq/fuzz/in /out/in
COPY jq/fuzz/fuzz.sh /out/fuzz.sh
COPY jq/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/jq /out/jq.cmplog && \
    file /out/jq && \
    /out/jq --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing jq'"]
