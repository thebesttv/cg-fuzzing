FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget bison uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: mawk" > /work/proj && \
    echo "version: 1.3.4-20240905" >> /work/proj && \
    echo "source: https://invisible-mirror.net/archives/mawk/mawk-1.3.4-20240905.tgz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://invisible-mirror.net/archives/mawk/mawk-1.3.4-20240905.tgz && \
    tar -xzf mawk-1.3.4-20240905.tgz && \
    rm mawk-1.3.4-20240905.tgz && \
    cp -a mawk-1.3.4-20240905 build-fuzz && \
    cp -a mawk-1.3.4-20240905 build-cmplog && \
    cp -a mawk-1.3.4-20240905 build-cov && \
    cp -a mawk-1.3.4-20240905 build-uftrace && \
    rm -rf mawk-1.3.4-20240905

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/mawk bin-fuzz && \
    /work/bin-fuzz -W version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/mawk bin-cmplog && \
    /work/bin-cmplog -W version

# Copy fuzzing resources
COPY mawk/fuzz/dict /work/dict
COPY mawk/fuzz/in /work/in
COPY mawk/fuzz/fuzz.sh /work/fuzz.sh
COPY mawk/fuzz/whatsup.sh /work/whatsup.sh
COPY mawk/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/mawk bin-cov && \
    /work/bin-cov -W version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/mawk bin-uftrace && \
    /work/bin-uftrace -W version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
