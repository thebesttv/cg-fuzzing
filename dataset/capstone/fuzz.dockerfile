FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract capstone 5.0.3 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.3.tar.gz && \
    tar -xzf 5.0.3.tar.gz && \
    rm 5.0.3.tar.gz

WORKDIR /src/capstone-5.0.3

# Build cstool with afl-clang-fast for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-fast CXX=afl-clang-fast++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCAPSTONE_BUILD_STATIC=ON \
        -DCAPSTONE_BUILD_CSTOOL=ON \
        -DCAPSTONE_BUILD_TESTS=OFF \
        -DCAPSTONE_BUILD_CSTEST=OFF

RUN cd build && make -j$(nproc)

# Install the cstool binary
RUN cp build/cstool /out/cstool

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf capstone-5.0.3 && \
    wget https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.3.tar.gz && \
    tar -xzf 5.0.3.tar.gz && \
    rm 5.0.3.tar.gz

WORKDIR /src/capstone-5.0.3

RUN mkdir build && cd build && \
    CC=afl-clang-fast CXX=afl-clang-fast++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCAPSTONE_BUILD_STATIC=ON \
        -DCAPSTONE_BUILD_CSTOOL=ON \
        -DCAPSTONE_BUILD_TESTS=OFF \
        -DCAPSTONE_BUILD_CSTEST=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/cstool /out/cstool.cmplog

# Copy fuzzing resources
COPY dataset/capstone/fuzz/dict /out/dict
COPY dataset/capstone/fuzz/in /out/in
COPY dataset/capstone/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/capstone/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/cstool /out/cstool.cmplog && \
    file /out/cstool && \
    /out/cstool -v

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing capstone cstool'"]
