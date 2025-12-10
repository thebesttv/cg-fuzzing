FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract lexbor v2.6.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/lexbor/lexbor/archive/refs/tags/v2.6.0.tar.gz && \
    tar -xzf v2.6.0.tar.gz && \
    rm v2.6.0.tar.gz

WORKDIR /src/lexbor-2.6.0

# Build library with afl-clang-lto
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DLEXBOR_BUILD_STATIC=ON \
        -DLEXBOR_BUILD_SHARED=OFF \
        -DLEXBOR_BUILD_EXAMPLES=OFF \
        -DLEXBOR_BUILD_TESTS=OFF

RUN cd build && make -j$(nproc)

# Copy harness and compile
COPY lexbor/fuzz/harness/afl_harness.c /src/afl_harness.c
RUN afl-clang-lto -O2 -I/src/lexbor-2.6.0/source \
    /src/afl_harness.c \
    -o /out/lexbor_html_fuzz \
    /src/lexbor-2.6.0/build/liblexbor_static.a -lm

# Build CMPLOG version
WORKDIR /src
RUN rm -rf lexbor-2.6.0 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/lexbor/lexbor/archive/refs/tags/v2.6.0.tar.gz && \
    tar -xzf v2.6.0.tar.gz && \
    rm v2.6.0.tar.gz

WORKDIR /src/lexbor-2.6.0

RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DLEXBOR_BUILD_STATIC=ON \
        -DLEXBOR_BUILD_SHARED=OFF \
        -DLEXBOR_BUILD_EXAMPLES=OFF \
        -DLEXBOR_BUILD_TESTS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Compile CMPLOG harness
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I/src/lexbor-2.6.0/source \
    /src/afl_harness.c \
    -o /out/lexbor_html_fuzz.cmplog \
    /src/lexbor-2.6.0/build/liblexbor_static.a -lm

# Copy fuzzing resources
COPY lexbor/fuzz/dict /out/dict
COPY lexbor/fuzz/in /out/in
COPY lexbor/fuzz/fuzz.sh /out/fuzz.sh
COPY lexbor/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/lexbor_html_fuzz /out/lexbor_html_fuzz.cmplog && \
    file /out/lexbor_html_fuzz

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing lexbor'"]
