FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake zlib1g-dev python3 uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build static zlib for static linking
RUN cd /tmp && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.zlib.net/zlib-1.3.1.tar.gz && \
    tar -xzf zlib-1.3.1.tar.gz && \
    cd zlib-1.3.1 && \
    ./configure --static && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/zlib-1.3.1*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: zziplib" > /work/proj && \
    echo "version: 0.13.80" >> /work/proj && \
    echo "source: https://github.com/gdraheim/zziplib/archive/refs/tags/v0.13.80.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/gdraheim/zziplib/archive/refs/tags/v0.13.80.tar.gz && \
    tar -xzf v0.13.80.tar.gz && \
    rm v0.13.80.tar.gz && \
    cp -a zziplib-0.13.80 build-fuzz && \
    cp -a zziplib-0.13.80 build-cmplog && \
    cp -a zziplib-0.13.80 build-cov && \
    cp -a zziplib-0.13.80 build-uftrace && \
    rm -rf zziplib-0.13.80

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTS=OFF && \
    make unzzip-big unzip-mem -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/bins/unzip-mem bin-fuzz && \
    /work/bin-fuzz --version || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTS=OFF && \
    AFL_LLVM_CMPLOG=1 make unzzip-big unzip-mem -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/bins/unzip-mem bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY zziplib/fuzz/dict /work/dict
COPY zziplib/fuzz/in /work/in
COPY zziplib/fuzz/fuzz.sh /work/fuzz.sh
COPY zziplib/fuzz/whatsup.sh /work/whatsup.sh
COPY zziplib/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY zziplib/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY zziplib/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTS=OFF && \
    make unzzip-big unzip-mem -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/bins/unzip-mem bin-cov && \
    /work/bin-cov --version || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTS=OFF && \
    make unzzip-big unzip-mem -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/build/bins/unzip-mem bin-uftrace && \
    /work/bin-uftrace --version || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
