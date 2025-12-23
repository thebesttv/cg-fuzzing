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
RUN echo "project: hoedown" > /work/proj && \
    echo "version: 3.0.7" >> /work/proj && \
    echo "source: https://github.com/hoedown/hoedown/archive/refs/tags/3.0.7.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/hoedown/hoedown/archive/refs/tags/3.0.7.tar.gz -O hoedown-3.0.7.tar.gz && \
    tar -xzf hoedown-3.0.7.tar.gz && \
    rm hoedown-3.0.7.tar.gz && \
    cp -a hoedown-3.0.7 build-fuzz && \
    cp -a hoedown-3.0.7 build-cmplog && \
    cp -a hoedown-3.0.7 build-cov && \
    cp -a hoedown-3.0.7 build-uftrace && \
    rm -rf hoedown-3.0.7

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2 -ansi -pedantic -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make hoedown

WORKDIR /work
RUN ln -s build-fuzz/hoedown bin-fuzz && \
    echo "# Test" | /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2 -ansi -pedantic -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make hoedown

WORKDIR /work
RUN ln -s build-cmplog/hoedown bin-cmplog && \
    echo "# Test" | /work/bin-cmplog

# Copy fuzzing resources
COPY hoedown/fuzz/dict /work/dict
COPY hoedown/fuzz/in /work/in
COPY hoedown/fuzz/fuzz.sh /work/fuzz.sh
COPY hoedown/fuzz/whatsup.sh /work/whatsup.sh
COPY hoedown/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -ansi -pedantic -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    make hoedown

WORKDIR /work
RUN ln -s build-cov/hoedown bin-cov && \
    echo "# Test" | /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer -ansi -pedantic -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make hoedown

WORKDIR /work
RUN ln -s build-uftrace/hoedown bin-uftrace && \
    echo "# Test" | /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
