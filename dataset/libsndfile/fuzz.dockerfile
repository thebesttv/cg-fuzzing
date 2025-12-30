FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils autogen libtool pkg-config python3 uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libsndfile" > /work/proj && \
    echo "version: 1.2.2" >> /work/proj && \
    echo "source: https://github.com/libsndfile/libsndfile/releases/download/1.2.2/libsndfile-1.2.2.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libsndfile/libsndfile/releases/download/1.2.2/libsndfile-1.2.2.tar.xz && \
    tar -xJf libsndfile-1.2.2.tar.xz && \
    rm libsndfile-1.2.2.tar.xz && \
    cp -a libsndfile-1.2.2 build-fuzz && \
    cp -a libsndfile-1.2.2 build-cmplog && \
    cp -a libsndfile-1.2.2 build-cov && \
    cp -a libsndfile-1.2.2 build-uftrace && \
    rm -rf libsndfile-1.2.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static \
    --disable-external-libs --disable-mpeg && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/programs/sndfile-info bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static \
    --disable-external-libs --disable-mpeg && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/programs/sndfile-info bin-cmplog

# Copy fuzzing resources
COPY libsndfile/fuzz/dict /work/dict
COPY libsndfile/fuzz/in /work/in
COPY libsndfile/fuzz/fuzz.sh /work/fuzz.sh
COPY libsndfile/fuzz/whatsup.sh /work/whatsup.sh
COPY libsndfile/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libsndfile/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libsndfile/fuzz/collect-branch.py /work/collect-branch.py
COPY libsndfile/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY libsndfile/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static \
    --disable-external-libs --disable-mpeg && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/programs/sndfile-info bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --prefix=/work/install-uftrace \
    --disable-external-libs --disable-mpeg && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/sndfile-info bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
