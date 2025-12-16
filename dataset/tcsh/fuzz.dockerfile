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
RUN echo "project: tcsh" > /work/proj && \
    echo "version: 6.24.16" >> /work/proj && \
    echo "source: https://astron.com/pub/tcsh/tcsh-6.24.16.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://astron.com/pub/tcsh/tcsh-6.24.16.tar.gz && \
    tar -xzf tcsh-6.24.16.tar.gz && \
    rm tcsh-6.24.16.tar.gz && \
    cp -a tcsh-6.24.16 build-fuzz && \
    cp -a tcsh-6.24.16 build-cmplog && \
    cp -a tcsh-6.24.16 build-cov && \
    cp -a tcsh-6.24.16 build-uftrace && \
    rm -rf tcsh-6.24.16

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/tcsh bin-fuzz && \
    echo "exit" | /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/tcsh bin-cmplog && \
    echo "exit" | /work/bin-cmplog

# Copy fuzzing resources
COPY tcsh/fuzz/dict /work/dict
COPY tcsh/fuzz/in /work/in
COPY tcsh/fuzz/fuzz.sh /work/fuzz.sh
COPY tcsh/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/tcsh bin-cov && \
    echo "exit" | /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/tcsh bin-uftrace && \
    echo "exit" | /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
