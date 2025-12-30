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
RUN echo "project: utf8proc" > /work/proj && \
    echo "version: 2.11.2" >> /work/proj && \
    echo "source: https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v2.11.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v2.11.2.tar.gz && \
    tar -xzf v2.11.2.tar.gz && \
    rm v2.11.2.tar.gz && \
    cp -a utf8proc-2.11.2 build-fuzz && \
    cp -a utf8proc-2.11.2 build-cmplog && \
    cp -a utf8proc-2.11.2 build-cov && \
    cp -a utf8proc-2.11.2 build-uftrace && \
    rm -rf utf8proc-2.11.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make libutf8proc.a && \
    afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o utf8proc_fuzz \
    test/fuzz_main.c test/fuzzer.c libutf8proc.a

WORKDIR /work
RUN ln -s build-fuzz/utf8proc_fuzz bin-fuzz && \
    /work/bin-fuzz -h 2>&1 | head -3

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make libutf8proc.a && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o utf8proc_fuzz \
    test/fuzz_main.c test/fuzzer.c libutf8proc.a

WORKDIR /work
RUN ln -s build-cmplog/utf8proc_fuzz bin-cmplog && \
    /work/bin-cmplog -h 2>&1 | head -3

# Copy fuzzing resources
COPY utf8proc/fuzz/dict /work/dict
COPY utf8proc/fuzz/in /work/in
COPY utf8proc/fuzz/fuzz.sh /work/fuzz.sh
COPY utf8proc/fuzz/whatsup.sh /work/whatsup.sh
COPY utf8proc/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY utf8proc/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY utf8proc/fuzz/collect-branch.py /work/collect-branch.py
COPY utf8proc/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    make libutf8proc.a && \
    clang \
    -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o utf8proc_fuzz \
    test/fuzz_main.c test/fuzzer.c libutf8proc.a

WORKDIR /work
RUN ln -s build-cov/utf8proc_fuzz bin-cov && \
    /work/bin-cov -h 2>&1 | head -3 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make libutf8proc.a && \
    clang \
    -g -O0 -pg -fno-omit-frame-pointer \
    -I. \
    -pg -Wl,--allow-multiple-definition \
    -o utf8proc_fuzz \
    test/fuzz_main.c test/fuzzer.c libutf8proc.a

WORKDIR /work
RUN ln -s build-uftrace/utf8proc_fuzz bin-uftrace && \
    /work/bin-uftrace -h 2>&1 | head -3 && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
