FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libwebp 1.5.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-1.5.0.tar.gz && \
    tar -xzf libwebp-1.5.0.tar.gz && \
    rm libwebp-1.5.0.tar.gz

WORKDIR /src/libwebp-1.5.0

# Build with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DWEBP_BUILD_CWEBP=OFF \
    -DWEBP_BUILD_DWEBP=ON \
    -DWEBP_BUILD_GIF2WEBP=OFF \
    -DWEBP_BUILD_IMG2WEBP=OFF \
    -DWEBP_BUILD_VWEBP=OFF \
    -DWEBP_BUILD_WEBPINFO=OFF \
    -DWEBP_BUILD_WEBPMUX=OFF \
    -DWEBP_BUILD_EXTRAS=OFF

RUN cd build && make -j$(nproc)

# Install the dwebp binary
RUN cp build/dwebp /out/dwebp

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf libwebp-1.5.0 && \
    wget https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-1.5.0.tar.gz && \
    tar -xzf libwebp-1.5.0.tar.gz && \
    rm libwebp-1.5.0.tar.gz

WORKDIR /src/libwebp-1.5.0

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DWEBP_BUILD_CWEBP=OFF \
    -DWEBP_BUILD_DWEBP=ON \
    -DWEBP_BUILD_GIF2WEBP=OFF \
    -DWEBP_BUILD_IMG2WEBP=OFF \
    -DWEBP_BUILD_VWEBP=OFF \
    -DWEBP_BUILD_WEBPINFO=OFF \
    -DWEBP_BUILD_WEBPMUX=OFF \
    -DWEBP_BUILD_EXTRAS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/dwebp /out/dwebp.cmplog

# Copy fuzzing resources
COPY dataset/libwebp/fuzz/dict /out/dict
COPY dataset/libwebp/fuzz/in /out/in
COPY dataset/libwebp/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libwebp/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/dwebp /out/dwebp.cmplog && \
    file /out/dwebp

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libwebp'"]
