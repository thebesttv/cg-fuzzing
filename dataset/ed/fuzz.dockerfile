FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget lzip uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: ed" > /work/proj && \
    echo "version: 1.22" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/ed/ed-1.22.tar.lz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/ed/ed-1.22.tar.lz && \
    tar --lzip -xf ed-1.22.tar.lz && \
    rm ed-1.22.tar.lz && \
    cp -a ed-1.22 build-fuzz && \
    cp -a ed-1.22 build-cmplog && \
    cp -a ed-1.22 build-cov && \
    cp -a ed-1.22 build-uftrace && \
    rm -rf ed-1.22

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./configure CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" && \
    make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/ed bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 ./configure CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" && \
    AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/ed bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY ed/fuzz/dict /work/dict
COPY ed/fuzz/in /work/in
COPY ed/fuzz/fuzz.sh /work/fuzz.sh
COPY ed/fuzz/whatsup.sh /work/whatsup.sh
COPY ed/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY ed/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY ed/fuzz/collect-branch.py /work/collect-branch.py
COPY ed/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY ed/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure && \
    make CC=clang CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/ed bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace && \
    make CC=clang CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" LDFLAGS="-pg -Wl,--allow-multiple-definition" -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/ed bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
