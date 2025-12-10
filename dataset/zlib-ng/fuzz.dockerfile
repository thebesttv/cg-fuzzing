FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract zlib-ng 2.3.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/zlib-ng/zlib-ng/archive/refs/tags/2.3.1.tar.gz && \
    tar -xzf 2.3.1.tar.gz && \
    rm 2.3.1.tar.gz

WORKDIR /src/zlib-ng-2.3.1

# Build zlib-ng with afl-clang-lto for fuzzing (main target binary)
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DZLIB_COMPAT=ON \
        -DWITH_GTEST=OFF

RUN cd build && make -j$(nproc)

# Install the binaries
RUN cp build/minigzip /out/minigzip

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf zlib-ng-2.3.1 && \
    wget https://github.com/zlib-ng/zlib-ng/archive/refs/tags/2.3.1.tar.gz && \
    tar -xzf 2.3.1.tar.gz && \
    rm 2.3.1.tar.gz

WORKDIR /src/zlib-ng-2.3.1

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DZLIB_COMPAT=ON \
        -DWITH_GTEST=OFF

RUN AFL_LLVM_CMPLOG=1 && cd build && make -j$(nproc)

# Install CMPLOG binary
RUN cp build/minigzip /out/minigzip.cmplog

# Copy fuzzing resources
COPY dataset/zlib-ng/fuzz/dict /out/dict
COPY dataset/zlib-ng/fuzz/in /out/in
COPY dataset/zlib-ng/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/zlib-ng/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/minigzip /out/minigzip.cmplog && \
    file /out/minigzip && \
    /out/minigzip -h || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing zlib-ng'"]
