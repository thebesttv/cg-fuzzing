FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: re2c" > /work/proj && \
    echo "version: 4.3" >> /work/proj && \
    echo "source: https://github.com/skvadrik/re2c/releases/download/4.3/re2c-4.3.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/skvadrik/re2c/releases/download/4.3/re2c-4.3.tar.xz && \
    tar -xf re2c-4.3.tar.xz && \
    rm re2c-4.3.tar.xz && \
    cp -a re2c-4.3 build-fuzz && \
    cp -a re2c-4.3 build-cmplog && \
    cp -a re2c-4.3 build-cov && \
    cp -a re2c-4.3 build-uftrace && \
    rm -rf re2c-4.3

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/re2c bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/re2c bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY 0-re2c/fuzz/dict /work/dict
COPY 0-re2c/fuzz/in /work/in
COPY 0-re2c/fuzz/fuzz.sh /work/fuzz.sh
COPY 0-re2c/fuzz/whatsup.sh /work/whatsup.sh
COPY 0-re2c/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY 0-re2c/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY 0-re2c/fuzz/collect-branch.py /work/collect-branch.py
COPY 0-re2c/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    CXXFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/re2c bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    CXXFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/re2c bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
