FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux && \
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
RUN echo "project: figlet" > /work/proj && \
    echo "version: 2.2.5" >> /work/proj && \
    echo "source: https://github.com/cmatsuoka/figlet/archive/refs/tags/2.2.5.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cmatsuoka/figlet/archive/refs/tags/2.2.5.tar.gz -O figlet-2.2.5.tar.gz && \
    tar -xzf figlet-2.2.5.tar.gz && \
    rm figlet-2.2.5.tar.gz && \
    cp -a figlet-2.2.5 build-fuzz && \
    cp -a figlet-2.2.5 build-cmplog && \
    cp -a figlet-2.2.5 build-cov && \
    cp -a figlet-2.2.5 build-uftrace && \
    rm -rf figlet-2.2.5

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto \
    LD=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/figlet bin-fuzz && \
    echo "Test" | FIGLET_FONTDIR=/work/build-fuzz/fonts /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    LD=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/figlet bin-cmplog && \
    echo "Test" | FIGLET_FONTDIR=/work/build-cmplog/fonts /work/bin-cmplog

# Copy fonts directory (figlet needs fonts at runtime)
RUN cp -r build-fuzz/fonts /work/fonts

# Copy fuzzing resources
COPY figlet/fuzz/dict /work/dict
COPY figlet/fuzz/in /work/in
COPY figlet/fuzz/fuzz.sh /work/fuzz.sh
COPY figlet/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang \
    LD=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/figlet bin-cov && \
    echo "Test" | FIGLET_FONTDIR=/work/build-cov/fonts /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang \
    LD=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    prefix=/work/install-uftrace \
    -j$(nproc) && \
    make prefix=/work/install-uftrace install

WORKDIR /work
RUN ln -s install-uftrace/bin/figlet bin-uftrace && \
    echo "Test" | FIGLET_FONTDIR=/work/install-uftrace/share/figlet /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
