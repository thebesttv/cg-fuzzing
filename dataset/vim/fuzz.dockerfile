FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
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
RUN echo "project: vim" > /work/proj && \
    echo "version: 9.1.0" >> /work/proj && \
    echo "source: https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz && \
    tar -xzf v9.1.0.tar.gz && \
    rm v9.1.0.tar.gz && \
    cp -a vim-9.1.0 build-fuzz && \
    cp -a vim-9.1.0 build-cmplog && \
    cp -a vim-9.1.0 build-cov && \
    cp -a vim-9.1.0 build-uftrace && \
    rm -rf vim-9.1.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --disable-gui \
        --disable-gtktest \
        --disable-xim \
        --disable-netbeans \
        --disable-channel \
        --without-x \
        --enable-multibyte && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/vim bin-fuzz && \
    /work/bin-fuzz --version | head -5

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --disable-gui \
        --disable-gtktest \
        --disable-xim \
        --disable-netbeans \
        --disable-channel \
        --without-x \
        --enable-multibyte && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/vim bin-cmplog && \
    /work/bin-cmplog --version | head -5

# Copy fuzzing resources
COPY vim/fuzz/dict /work/dict
COPY vim/fuzz/in /work/in
COPY vim/fuzz/fuzz.sh /work/fuzz.sh
COPY vim/fuzz/whatsup.sh /work/whatsup.sh
COPY vim/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY vim/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY vim/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --disable-gui \
        --disable-gtktest \
        --disable-xim \
        --disable-netbeans \
        --disable-channel \
        --without-x \
        --enable-multibyte && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/vim bin-cov && \
    /work/bin-cov --version | head -5 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --disable-gui \
        --disable-gtktest \
        --disable-xim \
        --disable-netbeans \
        --disable-channel \
        --without-x \
        --enable-multibyte && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/src/vim bin-uftrace && \
    /work/bin-uftrace --version | head -5 && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
