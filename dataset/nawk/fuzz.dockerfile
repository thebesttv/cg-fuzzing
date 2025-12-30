FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget bison uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: nawk" > /work/proj && \
    echo "version: 20240728" >> /work/proj && \
    echo "source: https://github.com/onetrueawk/awk/archive/refs/tags/20240728.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/onetrueawk/awk/archive/refs/tags/20240728.tar.gz -O nawk.tar.gz && \
    tar -xzf nawk.tar.gz && \
    rm nawk.tar.gz && \
    cp -a awk-20240728 build-fuzz && \
    cp -a awk-20240728 build-cmplog && \
    cp -a awk-20240728 build-cov && \
    cp -a awk-20240728 build-uftrace && \
    rm -rf awk-20240728

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto HOSTCC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-fuzz/a.out bin-fuzz && \
    /work/bin-fuzz 'BEGIN {print 1+1}' || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto HOSTCC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-cmplog/a.out bin-cmplog && \
    /work/bin-cmplog 'BEGIN {print 1+1}' || true

# Copy fuzzing resources
COPY nawk/fuzz/dict /work/dict
COPY nawk/fuzz/in /work/in
COPY nawk/fuzz/fuzz.sh /work/fuzz.sh
COPY nawk/fuzz/whatsup.sh /work/whatsup.sh
COPY nawk/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY nawk/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY nawk/fuzz/collect-branch.py /work/collect-branch.py
COPY nawk/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY nawk/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang HOSTCC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-cov/a.out bin-cov && \
    /work/bin-cov 'BEGIN {print 1+1}' || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang HOSTCC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-uftrace/a.out bin-uftrace && \
    /work/bin-uftrace 'BEGIN {print 1+1}' || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
