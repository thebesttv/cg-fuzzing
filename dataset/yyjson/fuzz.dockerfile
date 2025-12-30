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
RUN echo "project: yyjson" > /work/proj && \
    echo "version: 0.12.0" >> /work/proj && \
    echo "source: https://github.com/ibireme/yyjson/archive/refs/tags/0.12.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ibireme/yyjson/archive/refs/tags/0.12.0.tar.gz && \
    tar -xzf 0.12.0.tar.gz && \
    rm 0.12.0.tar.gz && \
    cp -a yyjson-0.12.0 build-fuzz && \
    cp -a yyjson-0.12.0 build-cmplog && \
    cp -a yyjson-0.12.0 build-cov && \
    cp -a yyjson-0.12.0 build-uftrace && \
    rm -rf yyjson-0.12.0

# Copy harness to all build directories
COPY yyjson/harness.c /work/build-fuzz/
COPY yyjson/harness.c /work/build-cmplog/
COPY yyjson/harness.c /work/build-cov/
COPY yyjson/harness.c /work/build-uftrace/

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DYYJSON_BUILD_TESTS=OFF && \
    make -j$(nproc) && \
    cd .. && \
    afl-clang-lto -O2 -I src \
    -static -Wl,--allow-multiple-definition \
    harness.c build/libyyjson.a -o yyjson_parse

WORKDIR /work
RUN ln -s build-fuzz/yyjson_parse bin-fuzz && \
    test -x /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DYYJSON_BUILD_TESTS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    cd .. && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I src \
    -static -Wl,--allow-multiple-definition \
    harness.c build/libyyjson.a -o yyjson_parse

WORKDIR /work
RUN ln -s build-cmplog/yyjson_parse bin-cmplog && \
    test -x /work/bin-cmplog

# Copy fuzzing resources
COPY yyjson/fuzz/dict /work/dict
COPY yyjson/fuzz/in /work/in
COPY yyjson/fuzz/fuzz.sh /work/fuzz.sh
COPY yyjson/fuzz/whatsup.sh /work/whatsup.sh
COPY yyjson/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY yyjson/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY yyjson/fuzz/collect-branch.py /work/collect-branch.py
COPY yyjson/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DYYJSON_BUILD_TESTS=OFF && \
    make -j$(nproc) && \
    cd .. && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I src -static -Wl,--allow-multiple-definition \
    harness.c build/libyyjson.a -o yyjson_parse

WORKDIR /work
RUN ln -s build-cov/yyjson_parse bin-cov && \
    test -x /work/bin-cov && \
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
    -DYYJSON_BUILD_TESTS=OFF && \
    make -j$(nproc) && \
    cd .. && \
    clang -g -O0 -pg -fno-omit-frame-pointer \
    -I src -Wl,--allow-multiple-definition \
    harness.c build/libyyjson.a -o yyjson_parse

WORKDIR /work
RUN ln -s build-uftrace/yyjson_parse bin-uftrace && \
    test -x /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
