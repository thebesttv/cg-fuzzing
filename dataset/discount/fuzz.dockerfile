FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
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
RUN echo "project: discount" > /work/proj && \
    echo "version: 3.0.1.2" >> /work/proj && \
    echo "source: https://github.com/Orc/discount/archive/refs/tags/v3.0.1.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Orc/discount/archive/refs/tags/v3.0.1.2.tar.gz && \
    tar -xzf v3.0.1.2.tar.gz && \
    rm v3.0.1.2.tar.gz && \
    cp -a discount-3.0.1.2 build-fuzz && \
    cp -a discount-3.0.1.2 build-cmplog && \
    cp -a discount-3.0.1.2 build-cov && \
    cp -a discount-3.0.1.2 build-uftrace && \
    rm -rf discount-3.0.1.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure.sh && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/markdown bin-fuzz && \
    /work/bin-fuzz -V | head -3

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure.sh && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/markdown bin-cmplog && \
    /work/bin-cmplog -V | head -3

# Copy fuzzing resources
COPY discount/fuzz/dict /work/dict
COPY discount/fuzz/in /work/in
COPY discount/fuzz/fuzz.sh /work/fuzz.sh
COPY discount/fuzz/whatsup.sh /work/whatsup.sh
COPY discount/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY discount/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY discount/fuzz/collect-branch.py /work/collect-branch.py
COPY discount/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure.sh && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/markdown bin-cov && \
    /work/bin-cov -V | head -3 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure.sh && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/markdown bin-uftrace && \
    /work/bin-uftrace -V | head -3 && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
