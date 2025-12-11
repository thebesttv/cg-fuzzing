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
RUN echo "project: bmake" > /work/proj && \
    echo "version: 20251111" >> /work/proj && \
    echo "source: http://www.crufty.net/ftp/pub/sjg/bmake-20251111.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 http://www.crufty.net/ftp/pub/sjg/bmake-20251111.tar.gz && \
    tar -xzf bmake-20251111.tar.gz && \
    rm bmake-20251111.tar.gz && \
    cp -r bmake build-fuzz && \
    cp -r bmake build-cmplog && \
    cp -r bmake build-cov && \
    cp -r bmake build-uftrace && \
    rm -rf bmake

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure && \
    sh ./make-bootstrap.sh

WORKDIR /work
RUN ln -s build-fuzz/bmake bin-fuzz && \
    echo "bmake binary created"

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure && \
    AFL_LLVM_CMPLOG=1 sh ./make-bootstrap.sh

WORKDIR /work
RUN ln -s build-cmplog/bmake bin-cmplog && \
    echo "bmake cmplog binary created"

# Copy fuzzing resources
COPY bmake/fuzz/dict /work/dict
COPY bmake/fuzz/in /work/in
COPY bmake/fuzz/fuzz.sh /work/fuzz.sh
COPY bmake/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure && \
    sh ./make-bootstrap.sh

WORKDIR /work
RUN ln -s build-cov/bmake bin-cov && \
    echo "bmake cov binary created" && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure && \
    sh ./make-bootstrap.sh

WORKDIR /work
RUN ln -s build-uftrace/bmake bin-uftrace && \
    echo "bmake uftrace binary created" && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
