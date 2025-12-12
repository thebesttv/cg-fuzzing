FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: flac" > /work/proj && \
    echo "version: 1.5.0" >> /work/proj && \
    echo "source: https://github.com/xiph/flac/releases/download/1.5.0/flac-1.5.0.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/flac/releases/download/1.5.0/flac-1.5.0.tar.xz && \
    tar -xJf flac-1.5.0.tar.xz && \
    rm flac-1.5.0.tar.xz && \
    cp -a flac-1.5.0 build-fuzz && \
    cp -a flac-1.5.0 build-cmplog && \
    cp -a flac-1.5.0 build-cov && \
    cp -a flac-1.5.0 build-uftrace && \
    rm -rf flac-1.5.0

# Build fuzz binary with afl-clang-fast
WORKDIR /work/build-fuzz
RUN echo 'int alloc_check_threshold = 2147483647, alloc_check_counter = 0, alloc_check_keep_failing = 0;' > /tmp/alloc_check_fuzz.c && \
    afl-clang-fast -c /tmp/alloc_check_fuzz.c -o /tmp/alloc_check_fuzz.o

RUN CC=afl-clang-fast \
    CXX=afl-clang-fast++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition /tmp/alloc_check_fuzz.o" \
    ./configure --disable-shared --enable-static --disable-ogg && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/flac/flac bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-fast + CMPLOG
WORKDIR /work/build-cmplog
RUN echo 'int alloc_check_threshold = 2147483647, alloc_check_counter = 0, alloc_check_keep_failing = 0;' > /tmp/alloc_check_cmplog.c && \
    afl-clang-fast -c /tmp/alloc_check_cmplog.c -o /tmp/alloc_check_cmplog.o

RUN CC=afl-clang-fast \
    CXX=afl-clang-fast++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition /tmp/alloc_check_cmplog.o" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --disable-ogg && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/flac/flac bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY flac/fuzz/dict /work/dict
COPY flac/fuzz/in /work/in
COPY flac/fuzz/fuzz.sh /work/fuzz.sh
COPY flac/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN echo 'int alloc_check_threshold = 2147483647, alloc_check_counter = 0, alloc_check_keep_failing = 0;' > /tmp/alloc_check_cov.c && \
    clang -c /tmp/alloc_check_cov.c -o /tmp/alloc_check_cov.o

RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    CXXFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition /tmp/alloc_check_cov.o" \
    ./configure --disable-shared --enable-static --disable-ogg && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/flac/flac bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN echo 'int alloc_check_threshold = 2147483647, alloc_check_counter = 0, alloc_check_keep_failing = 0;' > /tmp/alloc_check_uftrace.c && \
    clang -c /tmp/alloc_check_uftrace.c -o /tmp/alloc_check_uftrace.o

RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    CXXFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition /tmp/alloc_check_uftrace.o" \
    ./configure --disable-shared --enable-static --disable-ogg --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/flac bin-uftrace && \
    /work/bin-uftrace --version && \
    uftrace record /work/bin-uftrace --version && \
    uftrace report && \
    rm -rf uftrace.data gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
