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
RUN echo "project: readstat" > /work/proj && \
    echo "version: 1.1.9" >> /work/proj && \
    echo "source: https://github.com/WizardMac/ReadStat/releases/download/v1.1.9/readstat-1.1.9.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 \
    https://github.com/WizardMac/ReadStat/releases/download/v1.1.9/readstat-1.1.9.tar.gz && \
    tar -xzf readstat-1.1.9.tar.gz && \
    rm readstat-1.1.9.tar.gz && \
    cp -a readstat-1.1.9 build-fuzz && \
    cp -a readstat-1.1.9 build-cmplog && \
    cp -a readstat-1.1.9 build-cov && \
    cp -a readstat-1.1.9 build-uftrace && \
    rm -rf readstat-1.1.9

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -Wno-strict-prototypes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/readstat bin-fuzz && \
    /work/bin-fuzz --help || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -Wno-strict-prototypes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/readstat bin-cmplog && \
    /work/bin-cmplog --help || true

# Copy fuzzing resources
COPY readstat/fuzz/dict /work/dict
COPY readstat/fuzz/in /work/in
COPY readstat/fuzz/fuzz.sh /work/fuzz.sh
COPY readstat/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -Wno-strict-prototypes" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/readstat bin-cov && \
    /work/bin-cov --help || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer -Wno-strict-prototypes" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/readstat bin-uftrace && \
    /work/bin-uftrace --help || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
