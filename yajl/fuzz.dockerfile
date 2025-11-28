FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract yajl 2.1.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/lloyd/yajl/archive/refs/tags/2.1.0.tar.gz && \
    tar -xzf 2.1.0.tar.gz && \
    rm 2.1.0.tar.gz

WORKDIR /src/yajl-2.1.0

# Build json_verify with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF

# Build only the static library and json_verify (skip tests that link against dynamic lib)
RUN cd build && make -j$(nproc) yajl_s json_verify

# Install the json_verify binary
RUN find build -type f -name "json_verify" -executable -exec cp {} /out/json_verify \;

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf yajl-2.1.0 && \
    wget https://github.com/lloyd/yajl/archive/refs/tags/2.1.0.tar.gz && \
    tar -xzf 2.1.0.tar.gz && \
    rm 2.1.0.tar.gz

WORKDIR /src/yajl-2.1.0

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF

# Build only the static library and json_verify for CMPLOG
RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc) yajl_s json_verify

# Install CMPLOG binary
RUN find build -type f -name "json_verify" -executable -exec cp {} /out/json_verify.cmplog \;

# Copy fuzzing resources
COPY yajl/fuzz/dict /out/dict
COPY yajl/fuzz/in /out/in
COPY yajl/fuzz/fuzz.sh /out/fuzz.sh
COPY yajl/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/json_verify /out/json_verify.cmplog && \
    file /out/json_verify

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing json_verify'"]
