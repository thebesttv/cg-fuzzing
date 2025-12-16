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
RUN echo "project: capstone" > /work/proj && \
    echo "version: 5.0.3" >> /work/proj && \
    echo "source: https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.3.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.3.tar.gz && \
    tar -xzf 5.0.3.tar.gz && \
    rm 5.0.3.tar.gz && \
    cp -a capstone-5.0.3 build-fuzz && \
    cp -a capstone-5.0.3 build-cmplog && \
    cp -a capstone-5.0.3 build-cov && \
    cp -a capstone-5.0.3 build-uftrace && \
    rm -rf capstone-5.0.3

# Build Capstone library with afl-clang-lto (for fuzzing)
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCAPSTONE_BUILD_STATIC=ON \
        -DCAPSTONE_BUILD_CSTOOL=OFF \
        -DCAPSTONE_BUILD_TESTS=OFF \
        -DCAPSTONE_BUILD_CSTEST=OFF && \
    make -j$(nproc)

# Copy fuzzing harness source files
COPY capstone/fuzz/fuzz_harness.c /work/build-fuzz/
COPY capstone/fuzz/platform.c /work/build-fuzz/
COPY capstone/fuzz/platform.h /work/build-fuzz/

# Build custom fuzzing harness
WORKDIR /work/build-fuzz
RUN afl-clang-lto -O2 \
    -Iinclude \
    -o fuzz_harness \
    fuzz_harness.c platform.c \
    build/libcapstone.a \
    -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-fuzz/fuzz_harness bin-fuzz && \
    echo "Built custom fuzzing harness"

# Build Capstone library with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCAPSTONE_BUILD_STATIC=ON \
        -DCAPSTONE_BUILD_CSTOOL=OFF \
        -DCAPSTONE_BUILD_TESTS=OFF \
        -DCAPSTONE_BUILD_CSTEST=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy fuzzing harness source files
COPY capstone/fuzz/fuzz_harness.c /work/build-cmplog/
COPY capstone/fuzz/platform.c /work/build-cmplog/
COPY capstone/fuzz/platform.h /work/build-cmplog/

# Build custom fuzzing harness with CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 \
    -Iinclude \
    -o fuzz_harness \
    fuzz_harness.c platform.c \
    build/libcapstone.a \
    -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cmplog/fuzz_harness bin-cmplog && \
    echo "Built custom fuzzing harness with CMPLOG"

# Copy fuzzing resources
COPY capstone/fuzz/dict /work/dict
COPY capstone/fuzz/in /work/in
COPY capstone/fuzz/fuzz.sh /work/fuzz.sh
COPY capstone/fuzz/whatsup.sh /work/whatsup.sh

# Build Capstone library with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCAPSTONE_BUILD_STATIC=ON \
        -DCAPSTONE_BUILD_CSTOOL=OFF \
        -DCAPSTONE_BUILD_TESTS=OFF \
        -DCAPSTONE_BUILD_CSTEST=OFF && \
    make -j$(nproc)

# Copy fuzzing harness source files
COPY capstone/fuzz/fuzz_harness.c /work/build-cov/
COPY capstone/fuzz/platform.c /work/build-cov/
COPY capstone/fuzz/platform.h /work/build-cov/

# Build custom fuzzing harness with coverage
WORKDIR /work/build-cov
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -Iinclude \
    -o fuzz_harness \
    fuzz_harness.c platform.c \
    build/libcapstone.a \
    -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cov/fuzz_harness bin-cov && \
    rm -f *.profraw

# Build Capstone library with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCAPSTONE_BUILD_STATIC=ON \
        -DCAPSTONE_BUILD_CSTOOL=OFF \
        -DCAPSTONE_BUILD_TESTS=OFF \
        -DCAPSTONE_BUILD_CSTEST=OFF && \
    make -j$(nproc)

# Copy fuzzing harness source files
COPY capstone/fuzz/fuzz_harness.c /work/build-uftrace/
COPY capstone/fuzz/platform.c /work/build-uftrace/
COPY capstone/fuzz/platform.h /work/build-uftrace/

# Build custom fuzzing harness with profiling
WORKDIR /work/build-uftrace
RUN clang -g -O0 -pg -fno-omit-frame-pointer \
    -Iinclude \
    -o fuzz_harness \
    fuzz_harness.c platform.c \
    build/libcapstone.a \
    -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-uftrace/fuzz_harness bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
