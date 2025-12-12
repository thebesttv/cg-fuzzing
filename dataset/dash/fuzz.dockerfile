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
RUN echo "project: dash" > /work/proj && \
    echo "version: 0.5.12" >> /work/proj && \
    echo "source: http://gondor.apana.org.au/~herbert/dash/files/dash-0.5.12.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 http://gondor.apana.org.au/~herbert/dash/files/dash-0.5.12.tar.gz && \
    tar -xzf dash-0.5.12.tar.gz && \
    rm dash-0.5.12.tar.gz && \
    cp -a dash-0.5.12 build-fuzz && \
    cp -a dash-0.5.12 build-cmplog && \
    cp -a dash-0.5.12 build-cov && \
    cp -a dash-0.5.12 build-uftrace && \
    rm -rf dash-0.5.12

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/dash bin-fuzz && \
    /work/bin-fuzz -c 'echo test'

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/dash bin-cmplog && \
    /work/bin-cmplog -c 'echo test'

# Copy fuzzing resources
COPY dash/fuzz/dict /work/dict
COPY dash/fuzz/in /work/in
COPY dash/fuzz/fuzz.sh /work/fuzz.sh
COPY dash/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/dash bin-cov && \
    /work/bin-cov -c 'echo test' && \
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
RUN ln -s install-uftrace/bin/dash bin-uftrace && \
    /work/bin-uftrace -c 'echo test' && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
