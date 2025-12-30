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
RUN echo "project: http-parser" > /work/proj && \
    echo "version: 2.9.4" >> /work/proj && \
    echo "source: https://github.com/nodejs/http-parser/archive/refs/tags/v2.9.4.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/nodejs/http-parser/archive/refs/tags/v2.9.4.tar.gz && \
    tar -xzf v2.9.4.tar.gz && \
    rm v2.9.4.tar.gz && \
    cp -a http-parser-2.9.4 build-fuzz && \
    cp -a http-parser-2.9.4 build-cmplog && \
    cp -a http-parser-2.9.4 build-cov && \
    cp -a http-parser-2.9.4 build-uftrace && \
    rm -rf http-parser-2.9.4

# Copy fuzzing harness (same for all builds)
COPY http-parser/fuzz_harness.c /tmp/fuzz_harness.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN cp /tmp/fuzz_harness.c fuzz_harness.c && \
    afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o http_parser_fuzz \
    fuzz_harness.c http_parser.c

WORKDIR /work
RUN ln -s build-fuzz/http_parser_fuzz bin-fuzz && \
    echo "GET / HTTP/1.1" | /work/bin-fuzz /dev/stdin

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN cp /tmp/fuzz_harness.c fuzz_harness.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o http_parser_fuzz \
    fuzz_harness.c http_parser.c

WORKDIR /work
RUN ln -s build-cmplog/http_parser_fuzz bin-cmplog && \
    echo "GET / HTTP/1.1" | /work/bin-cmplog /dev/stdin

# Copy fuzzing resources
COPY http-parser/fuzz/dict /work/dict
COPY http-parser/fuzz/in /work/in
COPY http-parser/fuzz/fuzz.sh /work/fuzz.sh
COPY http-parser/fuzz/whatsup.sh /work/whatsup.sh
COPY http-parser/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY http-parser/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY http-parser/fuzz/collect-branch.py /work/collect-branch.py
COPY http-parser/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN cp /tmp/fuzz_harness.c fuzz_harness.c && \
    clang \
    -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I. \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    -o http_parser_fuzz \
    fuzz_harness.c http_parser.c

WORKDIR /work
RUN ln -s build-cov/http_parser_fuzz bin-cov && \
    echo "GET / HTTP/1.1" | /work/bin-cov /dev/stdin && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN cp /tmp/fuzz_harness.c fuzz_harness.c && \
    clang \
    -g -O0 -pg -fno-omit-frame-pointer \
    -I. \
    -pg -Wl,--allow-multiple-definition \
    -o http_parser_fuzz \
    fuzz_harness.c http_parser.c

WORKDIR /work
RUN ln -s build-uftrace/http_parser_fuzz bin-uftrace && \
    echo "GET / HTTP/1.1" | /work/bin-uftrace /dev/stdin && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
