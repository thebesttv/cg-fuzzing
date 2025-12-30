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
RUN echo "project: llhttp" > /work/proj && \
    echo "version: 9.2.1" >> /work/proj && \
    echo "source: https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.2.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.2.1.tar.gz && \
    tar -xzf v9.2.1.tar.gz && \
    rm v9.2.1.tar.gz && \
    cp -a llhttp-release-v9.2.1 build-fuzz && \
    cp -a llhttp-release-v9.2.1 build-cmplog && \
    cp -a llhttp-release-v9.2.1 build-cov && \
    cp -a llhttp-release-v9.2.1 build-uftrace && \
    rm -rf llhttp-release-v9.2.1

# Copy harness source
COPY llhttp/harness.c /work/harness.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_STATIC_LIBS=ON && \
    make -j$(nproc) && \
    cd .. && \
    afl-clang-lto -O2 -I./include -L./build -o llhttp_harness /work/harness.c build/libllhttp.a -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-fuzz/llhttp_harness bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_STATIC_LIBS=ON && \
    make -j$(nproc) && \
    cd .. && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I./include -L./build -o llhttp_harness /work/harness.c build/libllhttp.a -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cmplog/llhttp_harness bin-cmplog

# Copy fuzzing resources
COPY llhttp/fuzz/dict /work/dict
COPY llhttp/fuzz/in /work/in
COPY llhttp/fuzz/fuzz.sh /work/fuzz.sh
COPY llhttp/fuzz/whatsup.sh /work/whatsup.sh
COPY llhttp/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY llhttp/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY llhttp/fuzz/collect-branch.py /work/collect-branch.py
COPY llhttp/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_STATIC_LIBS=ON && \
    make -j$(nproc) && \
    cd .. && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I./include -L./build -o llhttp_harness /work/harness.c build/libllhttp.a -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cov/llhttp_harness bin-cov && \
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
        -DBUILD_STATIC_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/work/install-uftrace && \
    make -j$(nproc) && \
    cd .. && \
    clang -g -O0 -pg -fno-omit-frame-pointer -I./include -L./build -o llhttp_harness /work/harness.c build/libllhttp.a -pg -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-uftrace/llhttp_harness bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
