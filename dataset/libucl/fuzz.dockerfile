FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libucl 0.9.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/vstakhov/libucl/archive/refs/tags/0.9.2.tar.gz && \
    tar -xzf 0.9.2.tar.gz && \
    rm 0.9.2.tar.gz

WORKDIR /src/libucl-0.9.2

# Build libucl with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_UTILS=ON

RUN cd build && make -j$(nproc)

# Install the ucl_tool binary
RUN cp build/utils/ucl_tool /out/ucl_tool

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf libucl-0.9.2 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/vstakhov/libucl/archive/refs/tags/0.9.2.tar.gz && \
    tar -xzf 0.9.2.tar.gz && \
    rm 0.9.2.tar.gz

WORKDIR /src/libucl-0.9.2

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_UTILS=ON

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/utils/ucl_tool /out/ucl_tool.cmplog

# Copy fuzzing resources
COPY libucl/fuzz/dict /out/dict
COPY libucl/fuzz/in /out/in
COPY libucl/fuzz/fuzz.sh /out/fuzz.sh
COPY libucl/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/ucl_tool /out/ucl_tool.cmplog && \
    file /out/ucl_tool

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libucl'"]
