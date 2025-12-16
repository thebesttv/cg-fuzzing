FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: msgpack-c" > /work/proj && \
    echo "version: 6.1.0" >> /work/proj && \
    echo "source: https://github.com/msgpack/msgpack-c/archive/refs/tags/c-6.1.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget -O msgpack-c-6.1.0.tar.gz https://github.com/msgpack/msgpack-c/archive/refs/tags/c-6.1.0.tar.gz && \
    tar -xzf msgpack-c-6.1.0.tar.gz && \
    rm msgpack-c-6.1.0.tar.gz && \
    cp -a msgpack-c-c-6.1.0 build-fuzz && \
    cp -a msgpack-c-c-6.1.0 build-cmplog && \
    cp -a msgpack-c-c-6.1.0 build-cov && \
    cp -a msgpack-c-c-6.1.0 build-uftrace && \
    rm -rf msgpack-c-c-6.1.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DMSGPACK_BUILD_TESTS=OFF \
        -DMSGPACK_BUILD_EXAMPLES=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/example/lib_buffer_unpack bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DMSGPACK_BUILD_TESTS=OFF \
        -DMSGPACK_BUILD_EXAMPLES=ON && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/example/lib_buffer_unpack bin-cmplog

# Copy fuzzing resources
COPY msgpack-c/fuzz/dict /work/dict
COPY msgpack-c/fuzz/in /work/in
COPY msgpack-c/fuzz/fuzz.sh /work/fuzz.sh
COPY msgpack-c/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_CXX_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DMSGPACK_BUILD_TESTS=OFF \
        -DMSGPACK_BUILD_EXAMPLES=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/example/lib_buffer_unpack bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_CXX_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DMSGPACK_BUILD_TESTS=OFF \
        -DMSGPACK_BUILD_EXAMPLES=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/build/example/lib_buffer_unpack bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
