FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
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
RUN echo "project: json-c" > /work/proj && \
    echo "version: 0.18-20240915" >> /work/proj && \
    echo "source: https://github.com/json-c/json-c/archive/refs/tags/json-c-0.18-20240915.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/json-c/json-c/archive/refs/tags/json-c-0.18-20240915.tar.gz && \
    tar -xzf json-c-0.18-20240915.tar.gz && \
    rm json-c-0.18-20240915.tar.gz && \
    cp -a json-c-json-c-0.18-20240915 build-fuzz && \
    cp -a json-c-json-c-0.18-20240915 build-cmplog && \
    cp -a json-c-json-c-0.18-20240915 build-cov && \
    cp -a json-c-json-c-0.18-20240915 build-uftrace && \
    rm -rf json-c-json-c-0.18-20240915

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_APPS=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/apps/json_parse bin-fuzz && \
    /work/bin-fuzz --help || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_APPS=ON && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/apps/json_parse bin-cmplog && \
    /work/bin-cmplog --help || true

# Copy fuzzing resources
COPY json-c/fuzz/dict /work/dict
COPY json-c/fuzz/in /work/in
COPY json-c/fuzz/fuzz.sh /work/fuzz.sh
COPY json-c/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -Wno-unused-command-line-argument" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_APPS=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/apps/json_parse bin-cov && \
    /work/bin-cov --help || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer -Wno-unused-command-line-argument" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_APPS=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/build/apps/json_parse bin-uftrace && \
    /work/bin-uftrace --help || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
