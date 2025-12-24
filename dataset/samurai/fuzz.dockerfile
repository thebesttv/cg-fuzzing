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
RUN echo "project: samurai" > /work/proj && \
    echo "version: 1.2" >> /work/proj && \
    echo "source: https://github.com/michaelforney/samurai/releases/download/1.2/samurai-1.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/michaelforney/samurai/releases/download/1.2/samurai-1.2.tar.gz && \
    tar -xzf samurai-1.2.tar.gz && \
    rm samurai-1.2.tar.gz && \
    cp -a samurai-1.2 build-fuzz && \
    cp -a samurai-1.2 build-cmplog && \
    cp -a samurai-1.2 build-cov && \
    cp -a samurai-1.2 build-uftrace && \
    rm -rf samurai-1.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/samu bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/samu bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY samurai/fuzz/dict /work/dict
COPY samurai/fuzz/in /work/in
COPY samurai/fuzz/fuzz.sh /work/fuzz.sh
COPY samurai/fuzz/whatsup.sh /work/whatsup.sh
COPY samurai/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/samu bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/samu bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
