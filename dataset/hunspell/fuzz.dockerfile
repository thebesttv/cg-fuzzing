FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: hunspell" > /work/proj && \
    echo "version: 1.7.2" >> /work/proj && \
    echo "source: https://github.com/hunspell/hunspell/releases/download/v1.7.2/hunspell-1.7.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/hunspell/hunspell/releases/download/v1.7.2/hunspell-1.7.2.tar.gz && \
    tar -xzf hunspell-1.7.2.tar.gz && \
    rm hunspell-1.7.2.tar.gz && \
    cp -a hunspell-1.7.2 build-fuzz && \
    cp -a hunspell-1.7.2 build-cmplog && \
    cp -a hunspell-1.7.2 build-cov && \
    cp -a hunspell-1.7.2 build-uftrace && \
    rm -rf hunspell-1.7.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -static-libstdc++" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/tools/hunspell bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -static-libstdc++" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/tools/hunspell bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY hunspell/fuzz/dict /work/dict
COPY hunspell/fuzz/in /work/in
COPY hunspell/fuzz/fuzz.sh /work/fuzz.sh
COPY hunspell/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    CXXFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition -static-libstdc++" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/tools/hunspell bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    CXXFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition -static-libstdc++" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/src/tools/hunspell bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
