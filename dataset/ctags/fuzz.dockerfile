FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake pkg-config uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: ctags" > /work/proj && \
    echo "version: 6.2.1" >> /work/proj && \
    echo "source: https://github.com/universal-ctags/ctags/releases/download/v6.2.1/universal-ctags-6.2.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/universal-ctags/ctags/releases/download/v6.2.1/universal-ctags-6.2.1.tar.gz && \
    tar -xzf universal-ctags-6.2.1.tar.gz && \
    rm universal-ctags-6.2.1.tar.gz && \
    cp -a universal-ctags-6.2.1 build-fuzz && \
    cp -a universal-ctags-6.2.1 build-cmplog && \
    cp -a universal-ctags-6.2.1 build-cov && \
    cp -a universal-ctags-6.2.1 build-uftrace && \
    rm -rf universal-ctags-6.2.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure \
        --disable-shared \
        --disable-xml \
        --disable-json \
        --disable-yaml \
        --disable-seccomp \
        --disable-pcre2 && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/ctags bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure \
        --disable-shared \
        --disable-xml \
        --disable-json \
        --disable-yaml \
        --disable-seccomp \
        --disable-pcre2 && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/ctags bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY ctags/fuzz/dict /work/dict
COPY ctags/fuzz/in /work/in
COPY ctags/fuzz/fuzz.sh /work/fuzz.sh
COPY ctags/fuzz/whatsup.sh /work/whatsup.sh
COPY ctags/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY ctags/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY ctags/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure \
        --disable-shared \
        --disable-xml \
        --disable-json \
        --disable-yaml \
        --disable-seccomp \
        --disable-pcre2 && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/ctags bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure \
        --disable-shared \
        --disable-xml \
        --disable-json \
        --disable-yaml \
        --disable-seccomp \
        --disable-pcre2 && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/ctags bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
