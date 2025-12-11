FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux && \
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
RUN echo "project: oniguruma" > /work/proj && \
    echo "version: 6.9.10" >> /work/proj && \
    echo "source: https://github.com/kkos/oniguruma/releases/download/v6.9.10/onig-6.9.10.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/kkos/oniguruma/releases/download/v6.9.10/onig-6.9.10.tar.gz && \
    tar -xzf onig-6.9.10.tar.gz && \
    rm onig-6.9.10.tar.gz && \
    cp -r onig-6.9.10 build-fuzz && \
    cp -r onig-6.9.10 build-cmplog && \
    cp -r onig-6.9.10 build-cov && \
    cp -r onig-6.9.10 build-uftrace && \
    rm -rf onig-6.9.10

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

RUN cd sample && \
    afl-clang-lto -O2 -I../src -o simple simple.c ../src/.libs/libonig.a -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-fuzz/sample/simple bin-fuzz && \
    echo "test" | /work/bin-fuzz /dev/stdin

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN cd sample && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I../src -o simple simple.c ../src/.libs/libonig.a -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cmplog/sample/simple bin-cmplog && \
    echo "test" | /work/bin-cmplog /dev/stdin

# Copy fuzzing resources
COPY oniguruma/fuzz/dict /work/dict
COPY oniguruma/fuzz/in /work/in
COPY oniguruma/fuzz/fuzz.sh /work/fuzz.sh
COPY oniguruma/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

RUN cd sample && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I../src -o simple simple.c ../src/.libs/libonig.a -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cov/sample/simple bin-cov && \
    echo "test" | /work/bin-cov /dev/stdin && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/simple bin-uftrace && \
    echo "test" | /work/bin-uftrace /dev/stdin && \
    uftrace record /work/bin-uftrace /dev/stdin < /dev/null && \
    uftrace report && \
    rm -rf uftrace.data gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
