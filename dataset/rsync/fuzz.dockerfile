FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget python3 uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: rsync" > /work/proj && \
    echo "version: 3.3.0" >> /work/proj && \
    echo "source: https://download.samba.org/pub/rsync/src/rsync-3.3.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.samba.org/pub/rsync/src/rsync-3.3.0.tar.gz && \
    tar -xzf rsync-3.3.0.tar.gz && \
    rm rsync-3.3.0.tar.gz && \
    cp -a rsync-3.3.0 build-fuzz && \
    cp -a rsync-3.3.0 build-cmplog && \
    cp -a rsync-3.3.0 build-cov && \
    cp -a rsync-3.3.0 build-uftrace && \
    rm -rf rsync-3.3.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-xxhash --disable-zstd --disable-lz4 --disable-openssl && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/rsync bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-xxhash --disable-zstd --disable-lz4 --disable-openssl && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/rsync bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY rsync/fuzz/dict /work/dict
COPY rsync/fuzz/in /work/in
COPY rsync/fuzz/fuzz.sh /work/fuzz.sh
COPY rsync/fuzz/whatsup.sh /work/whatsup.sh
COPY rsync/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY rsync/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY rsync/fuzz/collect-branch.py /work/collect-branch.py
COPY rsync/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY rsync/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-xxhash --disable-zstd --disable-lz4 --disable-openssl && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/rsync bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --prefix=/work/install-uftrace --disable-xxhash --disable-zstd --disable-lz4 --disable-openssl && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/rsync bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
