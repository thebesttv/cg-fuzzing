FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget gettext uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: sysstat" > /work/proj && \
    echo "version: 12.7.6" >> /work/proj && \
    echo "source: https://github.com/sysstat/sysstat/archive/v12.7.6.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/sysstat/sysstat/archive/v12.7.6.tar.gz && \
    tar -xzf v12.7.6.tar.gz && \
    rm v12.7.6.tar.gz && \
    cp -a sysstat-12.7.6 build-fuzz && \
    cp -a sysstat-12.7.6 build-cmplog && \
    cp -a sysstat-12.7.6 build-cov && \
    cp -a sysstat-12.7.6 build-uftrace && \
    rm -rf sysstat-12.7.6

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-nls && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/sar bin-fuzz && \
    /work/bin-fuzz --help 2>&1 | head -5

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-nls && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/sar bin-cmplog && \
    /work/bin-cmplog --help 2>&1 | head -5

# Copy fuzzing resources
COPY sysstat/fuzz/dict /work/dict
COPY sysstat/fuzz/in /work/in
COPY sysstat/fuzz/fuzz.sh /work/fuzz.sh
COPY sysstat/fuzz/whatsup.sh /work/whatsup.sh
COPY sysstat/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-nls && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/sar bin-cov && \
    /work/bin-cov --help 2>&1 | head -5 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-nls && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/sar bin-uftrace && \
    /work/bin-uftrace --help 2>&1 | head -5 && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
