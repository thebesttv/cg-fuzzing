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
RUN echo "project: sqlite-harness" > /work/proj && \
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
    make sqlite3.c sqlite3.h -j$(nproc) && \
    afl-clang-lto -O2 -c sqlite3.c -o sqlite3.o -DSQLITE_OMIT_LOAD_EXTENSION && \
    afl-clang-lto -O2 -c test/ossfuzz.c -o ossfuzz.o -I. && \
    afl-clang-lto -O2 -fsanitize=fuzzer -static -Wl,--allow-multiple-definition \
        ossfuzz.o sqlite3.o -lpthread -lm -ldl -o sqlite_ossfuzz

WORKDIR /work
RUN ln -s build-fuzz/sqlite_ossfuzz bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-tcl --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make sqlite3.c sqlite3.h -j$(nproc) && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -c sqlite3.c -o sqlite3.o -DSQLITE_OMIT_LOAD_EXTENSION && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -c test/ossfuzz.c -o ossfuzz.o -I. && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -fsanitize=fuzzer -static -Wl,--allow-multiple-definition \
        ossfuzz.o sqlite3.o -lpthread -lm -ldl -o sqlite_ossfuzz

WORKDIR /work
RUN ln -s build-cmplog/sqlite_ossfuzz bin-cmplog

# Copy fuzzing resources
COPY sqlite-harness/fuzz/dict /work/dict
COPY sqlite-harness/fuzz/in /work/in
COPY sqlite-harness/fuzz/fuzz.sh /work/fuzz.sh
COPY sqlite-harness/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-tcl --disable-shared --enable-static && \
    make sqlite3.c sqlite3.h -j$(nproc) && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -c sqlite3.c -o sqlite3.o -DSQLITE_OMIT_LOAD_EXTENSION && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -c test/ossfuzz.c -o ossfuzz.o -I. && \
    clang -g -O0 -fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
        ossfuzz.o sqlite3.o -lpthread -lm -ldl -o sqlite_ossfuzz

WORKDIR /work
RUN ln -s build-cov/sqlite_ossfuzz bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -static -Wl,--allow-multiple-definition" \
    ./configure --disable-tcl --disable-shared --enable-static && \
    make sqlite3.c sqlite3.h -j$(nproc) && \
    clang -g -O0 -pg -fno-omit-frame-pointer -c sqlite3.c -o sqlite3.o -DSQLITE_OMIT_LOAD_EXTENSION && \
    clang -g -O0 -pg -fno-omit-frame-pointer -c test/ossfuzz.c -o ossfuzz.o -I. && \
    clang -g -O0 -fsanitize=fuzzer -pg -static -Wl,--allow-multiple-definition \
        ossfuzz.o sqlite3.o -lpthread -lm -ldl -o sqlite_ossfuzz

WORKDIR /work
RUN ln -s build-uftrace/sqlite_ossfuzz bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
