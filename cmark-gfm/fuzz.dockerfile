FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract cmark-gfm v0.29.0.gfm.13 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/github/cmark-gfm/archive/refs/tags/0.29.0.gfm.13.tar.gz && \
    tar -xzf 0.29.0.gfm.13.tar.gz && \
    rm 0.29.0.gfm.13.tar.gz

WORKDIR /src/cmark-gfm-0.29.0.gfm.13

# Build cmark-gfm with afl-clang-lto for fuzzing (main target binary)
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMARK_STATIC=ON \
        -DCMARK_SHARED=OFF \
        -DCMARK_TESTS=OFF

RUN cd build && make -j$(nproc)

# Install the cmark-gfm binary
RUN cp build/src/cmark-gfm /out/cmark-gfm

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf cmark-gfm-0.29.0.gfm.13 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/github/cmark-gfm/archive/refs/tags/0.29.0.gfm.13.tar.gz && \
    tar -xzf 0.29.0.gfm.13.tar.gz && \
    rm 0.29.0.gfm.13.tar.gz

WORKDIR /src/cmark-gfm-0.29.0.gfm.13

RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMARK_STATIC=ON \
        -DCMARK_SHARED=OFF \
        -DCMARK_TESTS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/src/cmark-gfm /out/cmark-gfm.cmplog

# Copy fuzzing resources
COPY cmark-gfm/fuzz/dict /out/dict
COPY cmark-gfm/fuzz/in /out/in
COPY cmark-gfm/fuzz/fuzz.sh /out/fuzz.sh
COPY cmark-gfm/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/cmark-gfm /out/cmark-gfm.cmplog && \
    file /out/cmark-gfm && \
    /out/cmark-gfm --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing cmark-gfm'"]
