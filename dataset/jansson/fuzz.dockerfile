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
RUN echo "project: jansson" > /work/proj && \
    echo "version: 2.14.1" >> /work/proj && \
    echo "source: https://github.com/akheron/jansson/releases/download/v2.14.1/jansson-2.14.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/akheron/jansson/releases/download/v2.14.1/jansson-2.14.1.tar.gz && \
    tar -xzf jansson-2.14.1.tar.gz && \
    rm jansson-2.14.1.tar.gz && \
    cp -a jansson-2.14.1 build-fuzz && \
    cp -a jansson-2.14.1 build-cmplog && \
    cp -a jansson-2.14.1 build-cov && \
    cp -a jansson-2.14.1 build-uftrace && \
    rm -rf jansson-2.14.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc) && \
    make -C test/bin json_process

WORKDIR /work
RUN ln -s build-fuzz/test/bin/json_process bin-fuzz && \
    echo '{}' | /work/bin-fuzz --strip /dev/stdin || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    AFL_LLVM_CMPLOG=1 make -C test/bin json_process

WORKDIR /work
RUN ln -s build-cmplog/test/bin/json_process bin-cmplog && \
    echo '{}' | /work/bin-cmplog --strip /dev/stdin || true

# Copy fuzzing resources
COPY jansson/fuzz/dict /work/dict
COPY jansson/fuzz/in /work/in
COPY jansson/fuzz/fuzz.sh /work/fuzz.sh
COPY jansson/fuzz/whatsup.sh /work/whatsup.sh
COPY jansson/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY jansson/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY jansson/fuzz/collect-branch.py /work/collect-branch.py
COPY jansson/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY jansson/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc) && \
    make -C test/bin json_process

WORKDIR /work
RUN ln -s build-cov/test/bin/json_process bin-cov && \
    echo '{}' | /work/bin-cov --strip /dev/stdin || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace --disable-shared --enable-static && \
    make -j$(nproc) && \
    make -C test/bin json_process && \
    make install

WORKDIR /work
RUN ln -s build-uftrace/test/bin/json_process bin-uftrace && \
    echo '{}' | /work/bin-uftrace --strip /dev/stdin || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
