FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libdeflate v1.25 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ebiggers/libdeflate/releases/download/v1.25/libdeflate-1.25.tar.gz && \
    tar -xzf libdeflate-1.25.tar.gz && \
    rm libdeflate-1.25.tar.gz

WORKDIR /src/libdeflate-1.25

# Build with CMake and AFL
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DLIBDEFLATE_BUILD_STATIC_LIB=ON \
        -DLIBDEFLATE_BUILD_SHARED_LIB=OFF \
        -DLIBDEFLATE_BUILD_GZIP=ON

RUN cd build && make -j$(nproc)

# Install the gzip binary (for decompression fuzzing)
RUN cp build/programs/libdeflate-gzip /out/libdeflate-gzip

# Build CMPLOG version
WORKDIR /src
RUN rm -rf libdeflate-1.25 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ebiggers/libdeflate/releases/download/v1.25/libdeflate-1.25.tar.gz && \
    tar -xzf libdeflate-1.25.tar.gz && \
    rm libdeflate-1.25.tar.gz

WORKDIR /src/libdeflate-1.25

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DLIBDEFLATE_BUILD_STATIC_LIB=ON \
        -DLIBDEFLATE_BUILD_SHARED_LIB=OFF \
        -DLIBDEFLATE_BUILD_GZIP=ON

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/programs/libdeflate-gzip /out/libdeflate-gzip.cmplog

# Copy fuzzing resources
COPY libdeflate/fuzz/dict /out/dict
COPY libdeflate/fuzz/in /out/in
COPY libdeflate/fuzz/fuzz.sh /out/fuzz.sh
COPY libdeflate/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/libdeflate-gzip /out/libdeflate-gzip.cmplog && \
    file /out/libdeflate-gzip && \
    /out/libdeflate-gzip -h || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libdeflate-gzip'"]
