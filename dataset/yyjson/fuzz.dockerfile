FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract yyjson v0.12.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ibireme/yyjson/archive/refs/tags/0.12.0.tar.gz && \
    tar -xzf 0.12.0.tar.gz && \
    rm 0.12.0.tar.gz

WORKDIR /src/yyjson-0.12.0

# Build with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DYYJSON_BUILD_TESTS=OFF

RUN cd build && make -j$(nproc)

# Copy the harness
COPY yyjson/harness.c harness.c

# Build the harness
RUN afl-clang-lto -O2 -I src \
    -static -Wl,--allow-multiple-definition \
    harness.c build/libyyjson.a -o yyjson_parse

# Install the binary
RUN cp yyjson_parse /out/yyjson_parse

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf yyjson-0.12.0 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ibireme/yyjson/archive/refs/tags/0.12.0.tar.gz && \
    tar -xzf 0.12.0.tar.gz && \
    rm 0.12.0.tar.gz

WORKDIR /src/yyjson-0.12.0

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DYYJSON_BUILD_TESTS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy the harness
COPY yyjson/harness.c harness.c

# Build the CMPLOG harness
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I src \
    -static -Wl,--allow-multiple-definition \
    harness.c build/libyyjson.a -o yyjson_parse.cmplog

# Install CMPLOG binary
RUN cp yyjson_parse.cmplog /out/yyjson_parse.cmplog

# Copy fuzzing resources
COPY yyjson/fuzz/dict /out/dict
COPY yyjson/fuzz/in /out/in
COPY yyjson/fuzz/fuzz.sh /out/fuzz.sh
COPY yyjson/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/yyjson_parse /out/yyjson_parse.cmplog && \
    file /out/yyjson_parse

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing yyjson'"]
