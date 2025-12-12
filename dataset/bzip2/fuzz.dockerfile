FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
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
RUN echo "project: bzip2" > /work/proj && \
    echo "version: 1.0.8" >> /work/proj && \
    echo "source: https://gitlab.com/bzip2/bzip2/-/archive/bzip2-1.0.8/bzip2-bzip2-1.0.8.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://gitlab.com/bzip2/bzip2/-/archive/bzip2-1.0.8/bzip2-bzip2-1.0.8.tar.gz && \
    tar -xzf bzip2-bzip2-1.0.8.tar.gz && \
    rm bzip2-bzip2-1.0.8.tar.gz && \
    cp -a bzip2-bzip2-1.0.8 build-fuzz && \
    cp -a bzip2-bzip2-1.0.8 build-cmplog && \
    cp -a bzip2-bzip2-1.0.8 build-cov && \
    cp -a bzip2-bzip2-1.0.8 build-uftrace && \
    rm -rf bzip2-bzip2-1.0.8

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make clean || true && \
    make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2 -Wall -Winline -D_FILE_OFFSET_BITS=64" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    bzip2

WORKDIR /work
RUN ln -s build-fuzz/bzip2 bin-fuzz && \
    /work/bin-fuzz --version || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN make clean || true && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2 -Wall -Winline -D_FILE_OFFSET_BITS=64" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    bzip2

WORKDIR /work
RUN ln -s build-cmplog/bzip2 bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY bzip2/fuzz/dict /work/dict
COPY bzip2/fuzz/in /work/in
COPY bzip2/fuzz/fuzz.sh /work/fuzz.sh
COPY bzip2/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make clean || true && \
    make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -Wall -Winline -D_FILE_OFFSET_BITS=64" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    bzip2

WORKDIR /work
RUN ln -s build-cov/bzip2 bin-cov && \
    /work/bin-cov --version || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make clean || true && \
    make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer -Wall -Winline -D_FILE_OFFSET_BITS=64" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    bzip2

WORKDIR /work
RUN ln -s build-uftrace/bzip2 bin-uftrace && \
    /work/bin-uftrace --version || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
