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
RUN echo "project: cjson" > /work/proj && \
    echo "version: 1.7.19" >> /work/proj && \
    echo "source: https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.19.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.19.tar.gz && \
    tar -xzf v1.7.19.tar.gz && \
    rm v1.7.19.tar.gz && \
    cp -a cJSON-1.7.19 build-fuzz && \
    cp -a cJSON-1.7.19 build-cmplog && \
    cp -a cJSON-1.7.19 build-cov && \
    cp -a cJSON-1.7.19 build-uftrace && \
    rm -rf cJSON-1.7.19

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_CJSON_TEST=OFF \
    -DENABLE_FUZZING=OFF && \
    make -j$(nproc) && \
    cd .. && \
    afl-clang-lto -O2 -I. -Lbuild fuzzing/afl.c -o afl_harness -lcjson \
        -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-fuzz/afl_harness bin-fuzz && \
    echo "cJSON afl harness binary created"

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_CJSON_TEST=OFF \
    -DENABLE_FUZZING=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    cd .. && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I. -Lbuild fuzzing/afl.c -o afl_harness.cmplog \
        -lcjson -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cmplog/afl_harness.cmplog bin-cmplog && \
    echo "cJSON afl harness cmplog binary created"

# Copy fuzzing resources
COPY cjson/fuzz/dict /work/dict
COPY cjson/fuzz/in /work/in
COPY cjson/fuzz/fuzz.sh /work/fuzz.sh
COPY cjson/fuzz/whatsup.sh /work/whatsup.sh
COPY cjson/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY cjson/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY cjson/fuzz/collect-branch.py /work/collect-branch.py
COPY cjson/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY cjson/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_CJSON_TEST=OFF \
    -DENABLE_FUZZING=OFF && \
    make -j$(nproc) && \
    cd .. && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I. -Lbuild fuzzing/afl.c -o afl_harness \
        -lcjson -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cov/afl_harness bin-cov && \
    echo "cJSON afl harness cov binary created" && \
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
    -DENABLE_CJSON_TEST=OFF \
    -DENABLE_FUZZING=OFF && \
    make -j$(nproc) && \
    cd .. && \
    clang -g -O0 -pg -fno-omit-frame-pointer -I. -Lbuild fuzzing/afl.c -o afl_harness \
        -lcjson -pg -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-uftrace/afl_harness bin-uftrace && \
    echo "cJSON afl harness uftrace binary created" && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
