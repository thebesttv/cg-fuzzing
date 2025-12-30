FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev pkg-config autoconf automake libtool uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: htop" > /work/proj && \
    echo "version: 3.4.1" >> /work/proj && \
    echo "source: https://github.com/htop-dev/htop/releases/download/3.4.1/htop-3.4.1.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/htop-dev/htop/releases/download/3.4.1/htop-3.4.1.tar.xz && \
    tar -xf htop-3.4.1.tar.xz && \
    rm htop-3.4.1.tar.xz && \
    cp -a htop-3.4.1 build-fuzz && \
    cp -a htop-3.4.1 build-cmplog && \
    cp -a htop-3.4.1 build-cov && \
    cp -a htop-3.4.1 build-uftrace && \
    rm -rf htop-3.4.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-unicode && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/htop bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --disable-unicode && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/htop bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY htop/fuzz/dict /work/dict
COPY htop/fuzz/in /work/in
COPY htop/fuzz/fuzz.sh /work/fuzz.sh
COPY htop/fuzz/whatsup.sh /work/whatsup.sh
COPY htop/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY htop/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY htop/fuzz/collect-branch.py /work/collect-branch.py
COPY htop/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY htop/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-unicode && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/htop bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-unicode --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/htop bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
