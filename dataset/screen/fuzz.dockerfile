FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: screen" > /work/proj && \
    echo "version: 5.0.1" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/screen/screen-5.0.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/screen/screen-5.0.1.tar.gz && \
    tar -xzf screen-5.0.1.tar.gz && \
    rm screen-5.0.1.tar.gz && \
    cp -r screen-5.0.1 build-fuzz && \
    cp -r screen-5.0.1 build-cmplog && \
    cp -r screen-5.0.1 build-cov && \
    cp -r screen-5.0.1 build-uftrace && \
    rm -rf screen-5.0.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-socket-dir --disable-pam && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/screen bin-fuzz && \
    /work/bin-fuzz -v

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-socket-dir --disable-pam && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/screen bin-cmplog && \
    /work/bin-cmplog -v

# Copy fuzzing resources
COPY screen/fuzz/dict /work/dict
COPY screen/fuzz/in /work/in
COPY screen/fuzz/fuzz.sh /work/fuzz.sh
COPY screen/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-socket-dir --disable-pam && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/screen bin-cov && \
    /work/bin-cov -v && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-socket-dir --disable-pam --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/screen bin-uftrace && \
    /work/bin-uftrace -v && \
    uftrace record /work/bin-uftrace -v && \
    uftrace report && \
    rm -rf uftrace.data gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
