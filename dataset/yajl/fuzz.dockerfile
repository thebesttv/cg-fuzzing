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
RUN echo "project: yajl" > /work/proj && \
    echo "version: 2.1.0" >> /work/proj && \
    echo "source: https://github.com/lloyd/yajl/archive/refs/tags/2.1.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/lloyd/yajl/archive/refs/tags/2.1.0.tar.gz && \
    tar -xzf 2.1.0.tar.gz && \
    rm 2.1.0.tar.gz && \
    cp -a yajl-2.1.0 build-fuzz && \
    cp -a yajl-2.1.0 build-cmplog && \
    cp -a yajl-2.1.0 build-cov && \
    cp -a yajl-2.1.0 build-uftrace && \
    rm -rf yajl-2.1.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc) yajl_s json_verify

WORKDIR /work
RUN find build-fuzz/build -type f -name "json_verify" -executable | head -1 | xargs -I {} ln -s {} bin-fuzz && \
    /work/bin-fuzz < /dev/null || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) yajl_s json_verify

WORKDIR /work
RUN find build-cmplog/build -type f -name "json_verify" -executable | head -1 | xargs -I {} ln -s {} bin-cmplog && \
    /work/bin-cmplog < /dev/null || true

# Copy fuzzing resources
COPY yajl/fuzz/dict /work/dict
COPY yajl/fuzz/in /work/in
COPY yajl/fuzz/fuzz.sh /work/fuzz.sh
COPY yajl/fuzz/whatsup.sh /work/whatsup.sh
COPY yajl/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY yajl/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY yajl/fuzz/collect-branch.py /work/collect-branch.py
COPY yajl/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY yajl/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc) yajl_s json_verify

WORKDIR /work
RUN find build-cov/build -type f -name "json_verify" -executable | head -1 | xargs -I {} ln -s {} bin-cov && \
    /work/bin-cov < /dev/null || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_INSTALL_PREFIX=/work/install-uftrace \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc) yajl_s json_verify && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/json_verify bin-uftrace && \
    /work/bin-uftrace < /dev/null || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
