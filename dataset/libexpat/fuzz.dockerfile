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
RUN echo "project: libexpat" > /work/proj && \
    echo "version: 2.7.3" >> /work/proj && \
    echo "source: https://github.com/libexpat/libexpat/releases/download/R_2_7_3/expat-2.7.3.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libexpat/libexpat/releases/download/R_2_7_3/expat-2.7.3.tar.gz && \
    tar -xzf expat-2.7.3.tar.gz && \
    rm expat-2.7.3.tar.gz && \
    cp -a expat-2.7.3 build-fuzz && \
    cp -a expat-2.7.3 build-cmplog && \
    cp -a expat-2.7.3 build-cov && \
    cp -a expat-2.7.3 build-uftrace && \
    rm -rf expat-2.7.3

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/xmlwf/xmlwf bin-fuzz && \
    /work/bin-fuzz --version || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/xmlwf/xmlwf bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY libexpat/fuzz/dict /work/dict
COPY libexpat/fuzz/in /work/in
COPY libexpat/fuzz/fuzz.sh /work/fuzz.sh
COPY libexpat/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/xmlwf/xmlwf bin-cov && \
    /work/bin-cov --version || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/xmlwf/xmlwf bin-uftrace && \
    /work/bin-uftrace --version || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
