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
RUN echo "project: jimtcl" > /work/proj && \
    echo "version: 0.83" >> /work/proj && \
    echo "source: https://github.com/msteveb/jimtcl/archive/refs/tags/0.83.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/msteveb/jimtcl/archive/refs/tags/0.83.tar.gz && \
    tar -xzf 0.83.tar.gz && \
    rm 0.83.tar.gz && \
    cp -a jimtcl-0.83 build-fuzz && \
    cp -a jimtcl-0.83 build-cmplog && \
    cp -a jimtcl-0.83 build-cov && \
    cp -a jimtcl-0.83 build-uftrace && \
    rm -rf jimtcl-0.83

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-ssl && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/jimsh bin-fuzz && \
    /work/bin-fuzz -e "puts hello"

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-ssl && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/jimsh bin-cmplog && \
    /work/bin-cmplog -e "puts hello"

# Copy fuzzing resources
COPY jimtcl/fuzz/dict /work/dict
COPY jimtcl/fuzz/in /work/in
COPY jimtcl/fuzz/fuzz.sh /work/fuzz.sh
COPY jimtcl/fuzz/whatsup.sh /work/whatsup.sh
COPY jimtcl/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY jimtcl/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY jimtcl/fuzz/collect-branch.py /work/collect-branch.py
COPY jimtcl/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-ssl && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/jimsh bin-cov && \
    /work/bin-cov -e "puts hello" && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-ssl --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/jimsh bin-uftrace && \
    /work/bin-uftrace -e "puts hello" && \
    uftrace record /work/bin-uftrace -e "puts hello" && \
    uftrace report && \
    rm -rf uftrace.data gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
