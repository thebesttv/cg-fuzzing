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
RUN echo "project: sqlite" > /work/proj && \
    echo "version: 3.51.0" >> /work/proj && \
    echo "source: https://github.com/sqlite/sqlite/archive/refs/tags/version-3.51.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/sqlite/sqlite/archive/refs/tags/version-3.51.0.tar.gz && \
    tar -xzf version-3.51.0.tar.gz && \
    rm version-3.51.0.tar.gz && \
    cp -a sqlite-version-3.51.0 build-fuzz && \
    cp -a sqlite-version-3.51.0 build-cmplog && \
    cp -a sqlite-version-3.51.0 build-cov && \
    cp -a sqlite-version-3.51.0 build-uftrace && \
    rm -rf sqlite-version-3.51.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-tcl --disable-shared --enable-static && \
    make sqlite3 -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/sqlite3 bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-tcl --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make sqlite3 -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/sqlite3 bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY sqlite/fuzz/dict /work/dict
COPY sqlite/fuzz/in /work/in
COPY sqlite/fuzz/fuzz.sh /work/fuzz.sh
COPY sqlite/fuzz/whatsup.sh /work/whatsup.sh
COPY sqlite/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-tcl --disable-shared --enable-static && \
    make sqlite3 -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/sqlite3 bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-tcl --prefix=/work/install-uftrace && \
    make sqlite3 -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/sqlite3 bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
