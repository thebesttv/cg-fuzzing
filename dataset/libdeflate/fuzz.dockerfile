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
RUN echo "project: libdeflate" > /work/proj && \
    echo "version: 1.25" >> /work/proj && \
    echo "source: https://github.com/ebiggers/libdeflate/releases/download/v1.25/libdeflate-1.25.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ebiggers/libdeflate/releases/download/v1.25/libdeflate-1.25.tar.gz && \
    tar -xzf libdeflate-1.25.tar.gz && \
    rm libdeflate-1.25.tar.gz && \
    cp -a libdeflate-1.25 build-fuzz && \
    cp -a libdeflate-1.25 build-cmplog && \
    cp -a libdeflate-1.25 build-cov && \
    cp -a libdeflate-1.25 build-uftrace && \
    rm -rf libdeflate-1.25

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DLIBDEFLATE_BUILD_STATIC_LIB=ON \
        -DLIBDEFLATE_BUILD_SHARED_LIB=OFF \
        -DLIBDEFLATE_BUILD_GZIP=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/programs/libdeflate-gzip bin-fuzz && \
    /work/bin-fuzz -h || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DLIBDEFLATE_BUILD_STATIC_LIB=ON \
        -DLIBDEFLATE_BUILD_SHARED_LIB=OFF \
        -DLIBDEFLATE_BUILD_GZIP=ON && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/programs/libdeflate-gzip bin-cmplog && \
    /work/bin-cmplog -h || true

# Copy fuzzing resources
COPY libdeflate/fuzz/dict /work/dict
COPY libdeflate/fuzz/in /work/in
COPY libdeflate/fuzz/fuzz.sh /work/fuzz.sh
COPY libdeflate/fuzz/whatsup.sh /work/whatsup.sh
COPY libdeflate/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DLIBDEFLATE_BUILD_STATIC_LIB=ON \
        -DLIBDEFLATE_BUILD_SHARED_LIB=OFF \
        -DLIBDEFLATE_BUILD_GZIP=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/programs/libdeflate-gzip bin-cov && \
    /work/bin-cov -h || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DLIBDEFLATE_BUILD_STATIC_LIB=ON \
        -DLIBDEFLATE_BUILD_SHARED_LIB=OFF \
        -DLIBDEFLATE_BUILD_GZIP=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/build/programs/libdeflate-gzip bin-uftrace && \
    /work/bin-uftrace -h || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
