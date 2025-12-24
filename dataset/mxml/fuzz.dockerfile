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
RUN echo "project: mxml" > /work/proj && \
    echo "version: 4.0.4" >> /work/proj && \
    echo "source: https://github.com/michaelrsweet/mxml/releases/download/v4.0.4/mxml-4.0.4.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/michaelrsweet/mxml/releases/download/v4.0.4/mxml-4.0.4.tar.gz && \
    tar -xzf mxml-4.0.4.tar.gz && \
    rm mxml-4.0.4.tar.gz && \
    cp -a mxml-4.0.4 build-fuzz && \
    cp -a mxml-4.0.4 build-cmplog && \
    cp -a mxml-4.0.4 build-cov && \
    cp -a mxml-4.0.4 build-uftrace && \
    rm -rf mxml-4.0.4

# Copy fuzzing harness to all build directories
COPY mxml/fuzz_mxml.c /work/build-fuzz/
COPY mxml/fuzz_mxml.c /work/build-cmplog/
COPY mxml/fuzz_mxml.c /work/build-cov/
COPY mxml/fuzz_mxml.c /work/build-uftrace/

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc) && \
    afl-clang-lto -O2 -I. -static -Wl,--allow-multiple-definition \
    -o fuzz_mxml fuzz_mxml.c libmxml4.a -lm -lpthread

WORKDIR /work
RUN ln -s build-fuzz/fuzz_mxml bin-fuzz && \
    test -x /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I. -static -Wl,--allow-multiple-definition \
    -o fuzz_mxml fuzz_mxml.c libmxml4.a -lm -lpthread

WORKDIR /work
RUN ln -s build-cmplog/fuzz_mxml bin-cmplog && \
    test -x /work/bin-cmplog

# Copy fuzzing resources
COPY mxml/fuzz/dict /work/dict
COPY mxml/fuzz/in /work/in
COPY mxml/fuzz/fuzz.sh /work/fuzz.sh
COPY mxml/fuzz/whatsup.sh /work/whatsup.sh
COPY mxml/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY mxml/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY mxml/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc) && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I. -static -Wl,--allow-multiple-definition \
    -o fuzz_mxml fuzz_mxml.c libmxml4.a -lm -lpthread

WORKDIR /work
RUN ln -s build-cov/fuzz_mxml bin-cov && \
    test -x /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc) && \
    clang -g -O0 -pg -fno-omit-frame-pointer \
    -I. -Wl,--allow-multiple-definition \
    -o fuzz_mxml fuzz_mxml.c libmxml4.a -lm -lpthread

WORKDIR /work
RUN ln -s build-uftrace/fuzz_mxml bin-uftrace && \
    test -x /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
