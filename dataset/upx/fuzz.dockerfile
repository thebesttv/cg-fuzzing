FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake ninja-build zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: upx" > /work/proj && \
    echo "version: 5.0.2" >> /work/proj && \
    echo "source: https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-src.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-src.tar.xz && \
    tar -xf upx-5.0.2-src.tar.xz && \
    rm upx-5.0.2-src.tar.xz && \
    cp -a upx-5.0.2-src build-fuzz && \
    cp -a upx-5.0.2-src build-cmplog && \
    cp -a upx-5.0.2-src build-cov && \
    cp -a upx-5.0.2-src build-uftrace && \
    rm -rf upx-5.0.2-src

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. -G Ninja \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DUPX_CONFIG_DISABLE_WERROR=ON && \
    ninja -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/upx bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. -G Ninja \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DUPX_CONFIG_DISABLE_WERROR=ON && \
    AFL_LLVM_CMPLOG=1 ninja -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/upx bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY upx/fuzz/dict /work/dict
COPY upx/fuzz/in /work/in
COPY upx/fuzz/fuzz.sh /work/fuzz.sh
COPY upx/fuzz/whatsup.sh /work/whatsup.sh
COPY upx/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    cmake .. -G Ninja \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_CXX_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DUPX_CONFIG_DISABLE_WERROR=ON && \
    ninja -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/upx bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    cmake .. -G Ninja \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_CXX_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DCMAKE_INSTALL_PREFIX=/work/install-uftrace \
        -DUPX_CONFIG_DISABLE_WERROR=ON && \
    ninja -j$(nproc) && \
    ninja install

WORKDIR /work
RUN ln -s install-uftrace/bin/upx bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
