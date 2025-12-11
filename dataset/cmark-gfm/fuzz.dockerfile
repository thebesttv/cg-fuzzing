FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux && \
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
RUN echo "project: cmark-gfm" > /work/proj && \
    echo "version: 0.29.0.gfm.13" >> /work/proj && \
    echo "source: https://github.com/github/cmark-gfm/archive/refs/tags/0.29.0.gfm.13.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/github/cmark-gfm/archive/refs/tags/0.29.0.gfm.13.tar.gz && \
    tar -xzf 0.29.0.gfm.13.tar.gz && \
    rm 0.29.0.gfm.13.tar.gz && \
    cp -r cmark-gfm-0.29.0.gfm.13 build-fuzz && \
    cp -r cmark-gfm-0.29.0.gfm.13 build-cmplog && \
    cp -r cmark-gfm-0.29.0.gfm.13 build-cov && \
    cp -r cmark-gfm-0.29.0.gfm.13 build-uftrace && \
    rm -rf cmark-gfm-0.29.0.gfm.13

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMARK_STATIC=ON \
        -DCMARK_SHARED=OFF \
        -DCMARK_TESTS=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/src/cmark-gfm bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMARK_STATIC=ON \
        -DCMARK_SHARED=OFF \
        -DCMARK_TESTS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/src/cmark-gfm bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY cmark-gfm/fuzz/dict /work/dict
COPY cmark-gfm/fuzz/in /work/in
COPY cmark-gfm/fuzz/fuzz.sh /work/fuzz.sh
COPY cmark-gfm/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMARK_STATIC=ON \
        -DCMARK_SHARED=OFF \
        -DCMARK_TESTS=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/src/cmark-gfm bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DCMAKE_INSTALL_PREFIX=/work/install-uftrace \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMARK_STATIC=ON \
        -DCMARK_SHARED=OFF \
        -DCMARK_TESTS=OFF && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/cmark-gfm bin-uftrace && \
    /work/bin-uftrace --version && \
    uftrace record /work/bin-uftrace --version && \
    uftrace report && \
    rm -rf uftrace.data gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
