FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract json-c 0.18 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/json-c/json-c/archive/refs/tags/json-c-0.18-20240915.tar.gz && \
    tar -xzf json-c-0.18-20240915.tar.gz && \
    rm json-c-0.18-20240915.tar.gz

WORKDIR /src/json-c-json-c-0.18-20240915

# Build json-c with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_APPS=ON

RUN cd build && make -j$(nproc)

# Install the json_parse binary
RUN cp build/apps/json_parse /out/json_parse

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf json-c-json-c-0.18-20240915 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/json-c/json-c/archive/refs/tags/json-c-0.18-20240915.tar.gz && \
    tar -xzf json-c-0.18-20240915.tar.gz && \
    rm json-c-0.18-20240915.tar.gz

WORKDIR /src/json-c-json-c-0.18-20240915

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_APPS=ON

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/apps/json_parse /out/json_parse.cmplog

# Copy fuzzing resources
COPY json-c/fuzz/dict /out/dict
COPY json-c/fuzz/in /out/in
COPY json-c/fuzz/fuzz.sh /out/fuzz.sh
COPY json-c/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/json_parse /out/json_parse.cmplog && \
    file /out/json_parse

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing json-c'"]
