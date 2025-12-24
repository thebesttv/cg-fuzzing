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
RUN echo "project: oniguruma" > /work/proj && \
    echo "version: 6.9.10" >> /work/proj && \
    echo "source: https://github.com/kkos/oniguruma/releases/download/v6.9.10/onig-6.9.10.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/kkos/oniguruma/releases/download/v6.9.10/onig-6.9.10.tar.gz && \
    tar -xzf onig-6.9.10.tar.gz && \
    rm onig-6.9.10.tar.gz && \
    cp -a onig-6.9.10 build-fuzz && \
    cp -a onig-6.9.10 build-cmplog && \
    cp -a onig-6.9.10 build-cov && \
    cp -a onig-6.9.10 build-uftrace && \
    rm -rf onig-6.9.10

# Build oniguruma with afl-clang-lto for fuzzing
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

# Build the sample utility with static linking
RUN cd sample && \
    afl-clang-lto -O2 -I../src -o simple simple.c ../src/.libs/libonig.a -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-fuzz/sample/simple bin-fuzz && \
    /work/bin-fuzz /work/in/test.txt

# Build oniguruma with afl-clang-lto + CMPLOG for cmplog
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build the sample utility with CMPLOG
RUN cd sample && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I../src -o simple simple.c ../src/.libs/libonig.a -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cmplog/sample/simple bin-cmplog && \
    /work/bin-cmplog /work/in/test.txt

# Copy fuzzing resources
COPY oniguruma/fuzz/dict /work/dict
COPY oniguruma/fuzz/in /work/in
COPY oniguruma/fuzz/fuzz.sh /work/fuzz.sh
COPY oniguruma/fuzz/whatsup.sh /work/whatsup.sh
COPY oniguruma/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build oniguruma with llvm-cov instrumentation for cov
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

# Build the sample utility with cov
RUN cd sample && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I../src -o simple simple.c ../src/.libs/libonig.a \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cov/sample/simple bin-cov && \
    /work/bin-cov /work/in/test.txt && \
    rm -f *.profraw

# Build oniguruma with profiling instrumentation for uftrace
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

# Build the sample utility with uftrace
RUN cd sample && \
    clang -g -O0 -pg -fno-omit-frame-pointer \
    -I../src -o simple simple.c ../src/.libs/libonig.a \
    -pg -Wl,--allow-multiple-definition && \
    mkdir -p /work/install-uftrace/bin && \
    cp simple /work/install-uftrace/bin/

WORKDIR /work
RUN ln -s install-uftrace/bin/simple bin-uftrace && \
    /work/bin-uftrace /work/in/test.txt && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
