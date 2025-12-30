FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: lmdb" > /work/proj && \
    echo "version: 0.9.31" >> /work/proj && \
    echo "source: https://github.com/LMDB/lmdb/archive/refs/tags/LMDB_0.9.31.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/LMDB/lmdb/archive/refs/tags/LMDB_0.9.31.tar.gz && \
    tar -xzf LMDB_0.9.31.tar.gz && \
    rm LMDB_0.9.31.tar.gz && \
    cp -a lmdb-LMDB_0.9.31 build-fuzz && \
    cp -a lmdb-LMDB_0.9.31 build-cmplog && \
    cp -a lmdb-LMDB_0.9.31 build-cov && \
    cp -a lmdb-LMDB_0.9.31 build-uftrace && \
    rm -rf lmdb-LMDB_0.9.31

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz/libraries/liblmdb
RUN make CC=afl-clang-lto \
    CFLAGS="-O2 -pthread" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -pthread" \
    mdb_load -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/libraries/liblmdb/mdb_load bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog/libraries/liblmdb
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2 -pthread" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -pthread" \
    mdb_load -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/libraries/liblmdb/mdb_load bin-cmplog

# Copy fuzzing resources
COPY lmdb/fuzz/dict /work/dict
COPY lmdb/fuzz/in /work/in
COPY lmdb/fuzz/fuzz.sh /work/fuzz.sh
COPY lmdb/fuzz/whatsup.sh /work/whatsup.sh
COPY lmdb/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY lmdb/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY lmdb/fuzz/collect-branch.py /work/collect-branch.py
COPY lmdb/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov/libraries/liblmdb
RUN make CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -pthread" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition -pthread" \
    mdb_load -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/libraries/liblmdb/mdb_load bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace/libraries/liblmdb
RUN make CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer -pthread" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition -pthread" \
    mdb_load -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/libraries/liblmdb/mdb_load bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
