FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract brotli v1.2.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/google/brotli/archive/refs/tags/v1.2.0.tar.gz && \
    tar -xzf v1.2.0.tar.gz && \
    rm v1.2.0.tar.gz

WORKDIR /src/brotli-1.2.0

# Build brotli with afl-clang-lto for fuzzing (main target binary)
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_BUILD_TYPE=Release

RUN cd build && make -j$(nproc)

# Install the brotli binary
RUN cp build/brotli /out/brotli

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf brotli-1.2.0 && \
    wget https://github.com/google/brotli/archive/refs/tags/v1.2.0.tar.gz && \
    tar -xzf v1.2.0.tar.gz && \
    rm v1.2.0.tar.gz

WORKDIR /src/brotli-1.2.0

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_BUILD_TYPE=Release

RUN AFL_LLVM_CMPLOG=1 cd build && make -j$(nproc)

# Install CMPLOG binary
RUN cp build/brotli /out/brotli.cmplog

# Copy fuzzing resources
COPY brotli/fuzz/dict /out/dict
COPY brotli/fuzz/in /out/in
COPY brotli/fuzz/fuzz.sh /out/fuzz.sh
COPY brotli/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/brotli /out/brotli.cmplog && \
    file /out/brotli && \
    /out/brotli --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing brotli'"]
