FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget yasm uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libvpx" > /work/proj && \
    echo "version: 1.14.1" >> /work/proj && \
    echo "source: https://github.com/webmproject/libvpx/archive/refs/tags/v1.14.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/webmproject/libvpx/archive/refs/tags/v1.14.1.tar.gz && \
    tar -xzf v1.14.1.tar.gz && \
    rm v1.14.1.tar.gz && \
    cp -a libvpx-1.14.1 build-fuzz && \
    cp -a libvpx-1.14.1 build-cmplog && \
    cp -a libvpx-1.14.1 build-cov && \
    cp -a libvpx-1.14.1 build-uftrace && \
    rm -rf libvpx-1.14.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --enable-static --disable-shared --enable-vp9-highbitdepth && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/vpxdec bin-fuzz && \
    /work/bin-fuzz --help || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --enable-static --disable-shared --enable-vp9-highbitdepth && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/vpxdec bin-cmplog && \
    /work/bin-cmplog --help || true

# Copy fuzzing resources
COPY libvpx/fuzz/dict /work/dict
COPY libvpx/fuzz/in /work/in
COPY libvpx/fuzz/fuzz.sh /work/fuzz.sh
COPY libvpx/fuzz/whatsup.sh /work/whatsup.sh
COPY libvpx/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libvpx/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libvpx/fuzz/collect-branch.py /work/collect-branch.py
COPY libvpx/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --enable-static --disable-shared --enable-vp9-highbitdepth && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/vpxdec bin-cov && \
    /work/bin-cov --help || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --enable-static --disable-shared --enable-vp9-highbitdepth --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/vpxdec bin-uftrace && \
    /work/bin-uftrace --help || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
