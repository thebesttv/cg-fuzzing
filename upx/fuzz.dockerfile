FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake ninja-build zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract upx v5.0.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-src.tar.xz && \
    tar -xf upx-5.0.2-src.tar.xz && \
    rm upx-5.0.2-src.tar.xz

WORKDIR /src/upx-5.0.2-src

# Build upx with afl-clang-lto for fuzzing (main target binary)
# Use static linking for better portability
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. -G Ninja \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DUPX_CONFIG_DISABLE_WERROR=ON

RUN cd build && ninja -j$(nproc)

# Install the upx binary
RUN cp build/upx /out/upx

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf upx-5.0.2-src && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-src.tar.xz && \
    tar -xf upx-5.0.2-src.tar.xz && \
    rm upx-5.0.2-src.tar.xz

WORKDIR /src/upx-5.0.2-src

RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. -G Ninja \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DUPX_CONFIG_DISABLE_WERROR=ON

RUN cd build && AFL_LLVM_CMPLOG=1 ninja -j$(nproc)

# Install CMPLOG binary
RUN cp build/upx /out/upx.cmplog

# Copy fuzzing resources
COPY upx/fuzz/dict /out/dict
COPY upx/fuzz/in /out/in
COPY upx/fuzz/fuzz.sh /out/fuzz.sh
COPY upx/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/upx /out/upx.cmplog && \
    file /out/upx && \
    /out/upx --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing upx'"]
