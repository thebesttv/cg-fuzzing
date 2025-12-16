FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget flex bison uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: recode" > /work/proj && \
    echo "version: 3.7.14" >> /work/proj && \
    echo "source: https://github.com/rrthomas/recode/releases/download/v3.7.14/recode-3.7.14.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/rrthomas/recode/releases/download/v3.7.14/recode-3.7.14.tar.gz && \
    tar -xzf recode-3.7.14.tar.gz && \
    rm recode-3.7.14.tar.gz && \
    cp -a recode-3.7.14 build-fuzz && \
    cp -a recode-3.7.14 build-cmplog && \
    cp -a recode-3.7.14 build-cov && \
    cp -a recode-3.7.14 build-uftrace && \
    rm -rf recode-3.7.14

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --without-libiconv-prefix && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/recode bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --without-libiconv-prefix && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/recode bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY recode/fuzz/dict /work/dict
COPY recode/fuzz/in /work/in
COPY recode/fuzz/fuzz.sh /work/fuzz.sh
COPY recode/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --without-libiconv-prefix && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/recode bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --without-libiconv-prefix && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/src/recode bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
