FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract msgpack-c v6.1.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget -O msgpack-c-6.1.0.tar.gz https://github.com/msgpack/msgpack-c/archive/refs/tags/c-6.1.0.tar.gz && \
    tar -xzf msgpack-c-6.1.0.tar.gz && \
    rm msgpack-c-6.1.0.tar.gz

WORKDIR /src/msgpack-c-c-6.1.0

# Build msgpack-c with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DMSGPACK_BUILD_TESTS=OFF \
        -DMSGPACK_BUILD_EXAMPLES=ON

WORKDIR /src/msgpack-c-c-6.1.0/build
RUN make -j$(nproc)

# Install the example binary (use lib_buffer_unpack as fuzzing target)
RUN cp example/lib_buffer_unpack /out/lib_buffer_unpack

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf msgpack-c-c-6.1.0 && \
    wget -O msgpack-c-6.1.0.tar.gz https://github.com/msgpack/msgpack-c/archive/refs/tags/c-6.1.0.tar.gz && \
    tar -xzf msgpack-c-6.1.0.tar.gz && \
    rm msgpack-c-6.1.0.tar.gz

WORKDIR /src/msgpack-c-c-6.1.0

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DMSGPACK_BUILD_TESTS=OFF \
        -DMSGPACK_BUILD_EXAMPLES=ON

WORKDIR /src/msgpack-c-c-6.1.0/build
RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp example/lib_buffer_unpack /out/lib_buffer_unpack.cmplog

# Copy fuzzing resources
COPY msgpack-c/fuzz/dict /out/dict
COPY msgpack-c/fuzz/in /out/in
COPY msgpack-c/fuzz/fuzz.sh /out/fuzz.sh
COPY msgpack-c/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/lib_buffer_unpack /out/lib_buffer_unpack.cmplog && \
    file /out/lib_buffer_unpack

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing msgpack-c'"]
