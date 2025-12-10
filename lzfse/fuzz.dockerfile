FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract lzfse 1.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/lzfse/lzfse/archive/refs/tags/lzfse-1.0.tar.gz && \
    tar -xzf lzfse-1.0.tar.gz && \
    rm lzfse-1.0.tar.gz

WORKDIR /src/lzfse-lzfse-1.0

# Build with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && make -j$(nproc)

# Install the lzfse binary
RUN cp build/lzfse /out/lzfse

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf lzfse-lzfse-1.0 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/lzfse/lzfse/archive/refs/tags/lzfse-1.0.tar.gz && \
    tar -xzf lzfse-1.0.tar.gz && \
    rm lzfse-1.0.tar.gz

WORKDIR /src/lzfse-lzfse-1.0

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/lzfse /out/lzfse.cmplog

# Copy fuzzing resources
COPY lzfse/fuzz/dict /out/dict
COPY lzfse/fuzz/in /out/in
COPY lzfse/fuzz/fuzz.sh /out/fuzz.sh
COPY lzfse/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/lzfse /out/lzfse.cmplog && \
    file /out/lzfse && \
    /out/lzfse -h || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing lzfse'"]
