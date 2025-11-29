FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract cmark 0.31.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/commonmark/cmark/archive/refs/tags/0.31.1.tar.gz && \
    tar -xzf 0.31.1.tar.gz && \
    rm 0.31.1.tar.gz

WORKDIR /src/cmark-0.31.1

# Build cmark with afl-clang-lto for fuzzing (main target binary)
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMARK_STATIC=ON \
    -DCMARK_TESTS=OFF

RUN cd build && make -j$(nproc)

# Install the cmark binary
RUN cp build/src/cmark /out/cmark

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf cmark-0.31.1 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/commonmark/cmark/archive/refs/tags/0.31.1.tar.gz && \
    tar -xzf 0.31.1.tar.gz && \
    rm 0.31.1.tar.gz

WORKDIR /src/cmark-0.31.1

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMARK_STATIC=ON \
    -DCMARK_TESTS=OFF

RUN AFL_LLVM_CMPLOG=1 cd build && make -j$(nproc)

# Install CMPLOG binary
RUN cp build/src/cmark /out/cmark.cmplog

# Copy fuzzing resources
COPY cmark/fuzz/dict /out/dict
COPY cmark/fuzz/in /out/in
COPY cmark/fuzz/fuzz.sh /out/fuzz.sh
COPY cmark/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/cmark /out/cmark.cmplog && \
    file /out/cmark && \
    /out/cmark --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing cmark'"]
