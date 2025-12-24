FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev libreadline-dev pkg-config uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: nnn" > /work/proj && \
    echo "version: 5.1" >> /work/proj && \
    echo "source: https://github.com/jarun/nnn/archive/refs/tags/v5.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jarun/nnn/archive/refs/tags/v5.1.tar.gz && \
    tar -xzf v5.1.tar.gz && \
    rm v5.1.tar.gz && \
    cp -a nnn-5.1 build-fuzz && \
    cp -a nnn-5.1 build-cmplog && \
    cp -a nnn-5.1 build-cov && \
    cp -a nnn-5.1 build-uftrace && \
    rm -rf nnn-5.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS_OPTIMIZATION="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    make strip -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/nnn bin-fuzz && \
    /work/bin-fuzz --version || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS_OPTIMIZATION="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make strip -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/nnn bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY nnn/fuzz/dict /work/dict
COPY nnn/fuzz/in /work/in
COPY nnn/fuzz/fuzz.sh /work/fuzz.sh
COPY nnn/fuzz/whatsup.sh /work/whatsup.sh
COPY nnn/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY nnn/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY nnn/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS_OPTIMIZATION="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -Wl,--allow-multiple-definition" \
    make strip -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/nnn bin-cov && \
    /work/bin-cov --version || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS_OPTIMIZATION="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make strip -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/nnn bin-uftrace && \
    /work/bin-uftrace --version || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
