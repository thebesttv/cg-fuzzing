FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev libzstd-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: file" > /work/proj && \
    echo "version: 5.46" >> /work/proj && \
    echo "source: https://astron.com/pub/file/file-5.46.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://astron.com/pub/file/file-5.46.tar.gz && \
    tar -xzf file-5.46.tar.gz && \
    rm file-5.46.tar.gz && \
    cp -a file-5.46 build-fuzz && \
    cp -a file-5.46 build-cmplog && \
    cp -a file-5.46 build-cov && \
    cp -a file-5.46 build-uftrace && \
    rm -rf file-5.46

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/file bin-fuzz && \
    cp build-fuzz/magic/magic.mgc magic.mgc && \
    /work/bin-fuzz -m /work/magic.mgc /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/file bin-cmplog && \
    /work/bin-cmplog -m /work/magic.mgc /work/bin-cmplog

# Copy fuzzing resources
COPY file/fuzz/dict /work/dict
COPY file/fuzz/in /work/in
COPY file/fuzz/fuzz.sh /work/fuzz.sh
COPY file/fuzz/whatsup.sh /work/whatsup.sh
COPY file/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY file/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY file/fuzz/collect-branch.py /work/collect-branch.py
COPY file/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY file/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/file bin-cov && \
    /work/bin-cov -m /work/magic.mgc /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/file bin-uftrace && \
    /work/bin-uftrace -m /work/magic.mgc /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
