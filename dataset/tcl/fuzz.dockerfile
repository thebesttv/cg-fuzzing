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
RUN echo "project: tcl" > /work/proj && \
    echo "version: 8.6.15" >> /work/proj && \
    echo "source: https://prdownloads.sourceforge.net/tcl/tcl8.6.15-src.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://prdownloads.sourceforge.net/tcl/tcl8.6.15-src.tar.gz && \
    tar -xzf tcl8.6.15-src.tar.gz && \
    rm tcl8.6.15-src.tar.gz && \
    cp -a tcl8.6.15 build-fuzz && \
    cp -a tcl8.6.15 build-cmplog && \
    cp -a tcl8.6.15 build-cov && \
    cp -a tcl8.6.15 build-uftrace && \
    rm -rf tcl8.6.15

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz/unix
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc) tclsh

WORKDIR /work
RUN ln -s build-fuzz/unix/tclsh bin-fuzz && \
    /work/bin-fuzz /dev/null < /dev/null 2>&1 || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog/unix
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) tclsh

WORKDIR /work
RUN ln -s build-cmplog/unix/tclsh bin-cmplog && \
    /work/bin-cmplog /dev/null < /dev/null 2>&1 || true

# Copy fuzzing resources
COPY tcl/fuzz/dict /work/dict
COPY tcl/fuzz/in /work/in
COPY tcl/fuzz/fuzz.sh /work/fuzz.sh
COPY tcl/fuzz/whatsup.sh /work/whatsup.sh
COPY tcl/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov/unix
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc) tclsh

WORKDIR /work
RUN ln -s build-cov/unix/tclsh bin-cov && \
    /work/bin-cov /dev/null < /dev/null 2>&1 || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace/unix
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc) tclsh

WORKDIR /work
RUN ln -s build-uftrace/unix/tclsh bin-uftrace && \
    /work/bin-uftrace /dev/null < /dev/null 2>&1 || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
