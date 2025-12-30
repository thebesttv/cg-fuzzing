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
RUN echo "project: jo" > /work/proj && \
    echo "version: 1.9" >> /work/proj && \
    echo "source: https://github.com/jpmens/jo/releases/download/1.9/jo-1.9.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jpmens/jo/releases/download/1.9/jo-1.9.tar.gz && \
    tar -xzf jo-1.9.tar.gz && \
    rm jo-1.9.tar.gz && \
    cp -a jo-1.9 build-fuzz && \
    cp -a jo-1.9 build-cmplog && \
    cp -a jo-1.9 build-cov && \
    cp -a jo-1.9 build-uftrace && \
    rm -rf jo-1.9

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/jo bin-fuzz && \
    /work/bin-fuzz -v

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/jo bin-cmplog && \
    /work/bin-cmplog -v

# Copy fuzzing resources
COPY jo/fuzz/dict /work/dict
COPY jo/fuzz/in /work/in
COPY jo/fuzz/fuzz.sh /work/fuzz.sh
COPY jo/fuzz/whatsup.sh /work/whatsup.sh
COPY jo/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY jo/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY jo/fuzz/collect-branch.py /work/collect-branch.py
COPY jo/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY jo/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/jo bin-cov && \
    /work/bin-cov -v && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace --disable-shared && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/jo bin-uftrace && \
    /work/bin-uftrace -v && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
