FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libpng-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: fig2dev" > /work/proj && \
    echo "version: 3.2.9" >> /work/proj && \
    echo "source: https://sourceforge.net/projects/mcj/files/fig2dev-3.2.9.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://sourceforge.net/projects/mcj/files/fig2dev-3.2.9.tar.xz && \
    tar -xf fig2dev-3.2.9.tar.xz && \
    rm fig2dev-3.2.9.tar.xz && \
    cp -a fig2dev-3.2.9 build-fuzz && \
    cp -a fig2dev-3.2.9 build-cmplog && \
    cp -a fig2dev-3.2.9 build-cov && \
    cp -a fig2dev-3.2.9 build-uftrace && \
    rm -rf fig2dev-3.2.9

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/fig2dev/fig2dev bin-fuzz && \
    /work/bin-fuzz -h || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/fig2dev/fig2dev bin-cmplog && \
    /work/bin-cmplog -h || true

# Copy fuzzing resources
COPY fig2dev/fuzz/dict /work/dict
COPY fig2dev/fuzz/in /work/in
COPY fig2dev/fuzz/fuzz.sh /work/fuzz.sh
COPY fig2dev/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/fig2dev/fig2dev bin-cov && \
    /work/bin-cov -h || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/fig2dev bin-uftrace && \
    /work/bin-uftrace -h || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
