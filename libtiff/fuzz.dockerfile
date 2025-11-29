FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libtiff v4.7.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://download.osgeo.org/libtiff/tiff-4.7.0.tar.gz && \
    tar -xzf tiff-4.7.0.tar.gz && \
    rm tiff-4.7.0.tar.gz

WORKDIR /src/tiff-4.7.0

# Build tiffinfo with afl-clang-lto for fuzzing
RUN mkdir cmake_build && cd cmake_build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DBUILD_SHARED_LIBS=OFF \
        -Dtiff-docs=OFF \
        -Dtiff-tests=OFF \
        -Djpeg=OFF \
        -Djbig=OFF \
        -Dlerc=OFF \
        -Dlzma=OFF \
        -Dzstd=OFF \
        -Dwebp=OFF \
        -Dzlib=OFF

RUN cd cmake_build && make -j$(nproc)

# Install the tiffinfo binary
RUN cp cmake_build/tools/tiffinfo /out/tiffinfo

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf tiff-4.7.0 && \
    wget https://download.osgeo.org/libtiff/tiff-4.7.0.tar.gz && \
    tar -xzf tiff-4.7.0.tar.gz && \
    rm tiff-4.7.0.tar.gz

WORKDIR /src/tiff-4.7.0

RUN mkdir cmake_build && cd cmake_build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DBUILD_SHARED_LIBS=OFF \
        -Dtiff-docs=OFF \
        -Dtiff-tests=OFF \
        -Djpeg=OFF \
        -Djbig=OFF \
        -Dlerc=OFF \
        -Dlzma=OFF \
        -Dzstd=OFF \
        -Dwebp=OFF \
        -Dzlib=OFF

RUN AFL_LLVM_CMPLOG=1 cd cmake_build && make -j$(nproc)

# Install CMPLOG binary
RUN cp cmake_build/tools/tiffinfo /out/tiffinfo.cmplog

# Copy fuzzing resources
COPY libtiff/fuzz/dict /out/dict
COPY libtiff/fuzz/in /out/in
COPY libtiff/fuzz/fuzz.sh /out/fuzz.sh
COPY libtiff/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/tiffinfo /out/tiffinfo.cmplog && \
    file /out/tiffinfo && \
    /out/tiffinfo --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tiffinfo'"]
