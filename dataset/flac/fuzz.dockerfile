FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
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

# Create alloc_check symbols for fuzzing mode
RUN echo 'int alloc_check_threshold = 2147483647, alloc_check_counter = 0, alloc_check_keep_failing = 0;' > /tmp/alloc_check.c

# Build fuzz binary with afl-clang-lto
RUN afl-clang-lto -c /tmp/alloc_check.c -o /tmp/alloc_check_fuzz.o

WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition /tmp/alloc_check_fuzz.o" \
    ./configure --disable-shared --enable-static --disable-ogg && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/flac/flac bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
RUN afl-clang-lto -c /tmp/alloc_check.c -o /tmp/alloc_check_cmplog.o

WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
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
RUN clang -c /tmp/alloc_check.c -o /tmp/alloc_check_cov.o

WORKDIR /work/build-cov
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
RUN clang -c /tmp/alloc_check.c -o /tmp/alloc_check_uftrace.o

WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    CXXFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition /tmp/alloc_check_uftrace.o" \
    ./configure --disable-shared --enable-static --disable-ogg && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/src/flac/flac bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
