FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract wren 0.4.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/wren-lang/wren/archive/refs/tags/0.4.0.tar.gz && \
    tar -xzf 0.4.0.tar.gz && \
    rm 0.4.0.tar.gz

WORKDIR /src/wren-0.4.0/projects/make

# Build wren with afl-clang-lto
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    make config=release_64bit wren

# Copy the harness
COPY wren/harness.c /src/wren-0.4.0/harness.c

WORKDIR /src/wren-0.4.0

# Build the harness
RUN afl-clang-lto -O2 -I src/include \
    -static -Wl,--allow-multiple-definition \
    harness.c lib/libwren.a -lm -o wren_parse

# Install the binary
RUN cp wren_parse /out/wren_parse

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf wren-0.4.0 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/wren-lang/wren/archive/refs/tags/0.4.0.tar.gz && \
    tar -xzf 0.4.0.tar.gz && \
    rm 0.4.0.tar.gz

WORKDIR /src/wren-0.4.0/projects/make

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    AFL_LLVM_CMPLOG=1 \
    make config=release_64bit wren

# Copy the harness
COPY wren/harness.c /src/wren-0.4.0/harness.c

WORKDIR /src/wren-0.4.0

# Build the CMPLOG harness
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I src/include \
    -static -Wl,--allow-multiple-definition \
    harness.c lib/libwren.a -lm -o wren_parse.cmplog

# Install CMPLOG binary
RUN cp wren_parse.cmplog /out/wren_parse.cmplog

# Copy fuzzing resources
COPY wren/fuzz/dict /out/dict
COPY wren/fuzz/in /out/in
COPY wren/fuzz/fuzz.sh /out/fuzz.sh
COPY wren/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/wren_parse /out/wren_parse.cmplog && \
    file /out/wren_parse

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing wren'"]
