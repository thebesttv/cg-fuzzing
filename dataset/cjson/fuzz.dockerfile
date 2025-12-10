FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract cJSON 1.7.19 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.19.tar.gz && \
    tar -xzf v1.7.19.tar.gz && \
    rm v1.7.19.tar.gz

WORKDIR /src/cJSON-1.7.19

# Build with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_CJSON_TEST=OFF \
    -DENABLE_FUZZING=OFF

RUN cd build && make -j$(nproc)

# Build the afl harness manually
RUN afl-clang-lto -O2 -I. -Lbuild fuzzing/afl.c -o afl_harness -lcjson \
    -static -Wl,--allow-multiple-definition

# Install the afl binary
RUN cp afl_harness /out/cjson_afl

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf cJSON-1.7.19 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.19.tar.gz && \
    tar -xzf v1.7.19.tar.gz && \
    rm v1.7.19.tar.gz

WORKDIR /src/cJSON-1.7.19

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_CJSON_TEST=OFF \
    -DENABLE_FUZZING=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build the CMPLOG afl harness manually
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I. -Lbuild fuzzing/afl.c -o afl_harness.cmplog \
    -lcjson -static -Wl,--allow-multiple-definition

# Install CMPLOG binary
RUN cp afl_harness.cmplog /out/cjson_afl.cmplog

# Copy fuzzing resources
COPY cjson/fuzz/dict /out/dict
COPY cjson/fuzz/in /out/in
COPY cjson/fuzz/fuzz.sh /out/fuzz.sh
COPY cjson/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/cjson_afl /out/cjson_afl.cmplog && \
    file /out/cjson_afl

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing cJSON'"]
