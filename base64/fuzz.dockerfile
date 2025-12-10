FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract base64 v0.5.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/aklomp/base64/archive/refs/tags/v0.5.2.tar.gz && \
    tar -xzf v0.5.2.tar.gz && \
    rm v0.5.2.tar.gz

WORKDIR /src/base64-0.5.2

# Build base64 with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBASE64_BUILD_CLI=ON

RUN cd build && make -j$(nproc)

# Install the base64 binary
RUN cp build/bin/base64 /out/base64

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf base64-0.5.2 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/aklomp/base64/archive/refs/tags/v0.5.2.tar.gz && \
    tar -xzf v0.5.2.tar.gz && \
    rm v0.5.2.tar.gz

WORKDIR /src/base64-0.5.2

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBASE64_BUILD_CLI=ON

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/bin/base64 /out/base64.cmplog

# Copy fuzzing resources
COPY base64/fuzz/dict /out/dict
COPY base64/fuzz/in /out/in
COPY base64/fuzz/fuzz.sh /out/fuzz.sh
COPY base64/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/base64 /out/base64.cmplog && \
    file /out/base64

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing base64'"]
