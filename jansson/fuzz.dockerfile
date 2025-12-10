FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract jansson 2.14.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/akheron/jansson/releases/download/v2.14.1/jansson-2.14.1.tar.gz && \
    tar -xzf jansson-2.14.1.tar.gz && \
    rm jansson-2.14.1.tar.gz

WORKDIR /src/jansson-2.14.1

# Build with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc) && \
    make -C test/bin json_process

# Install the json_process binary
RUN cp test/bin/json_process /out/json_process

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf jansson-2.14.1 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/akheron/jansson/releases/download/v2.14.1/jansson-2.14.1.tar.gz && \
    tar -xzf jansson-2.14.1.tar.gz && \
    rm jansson-2.14.1.tar.gz

WORKDIR /src/jansson-2.14.1

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    AFL_LLVM_CMPLOG=1 make -C test/bin json_process

# Install CMPLOG binary
RUN cp test/bin/json_process /out/json_process.cmplog

# Copy fuzzing resources
COPY jansson/fuzz/dict /out/dict
COPY jansson/fuzz/in /out/in
COPY jansson/fuzz/fuzz.sh /out/fuzz.sh
COPY jansson/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/json_process /out/json_process.cmplog && \
    file /out/json_process

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing jansson (json_process)'"]
