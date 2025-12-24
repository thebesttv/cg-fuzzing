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
RUN echo "project: entr" > /work/proj && \
    echo "version: 5.6" >> /work/proj && \
    echo "source: https://github.com/eradman/entr/archive/refs/tags/5.6.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/eradman/entr/archive/refs/tags/5.6.tar.gz && \
    tar -xzf 5.6.tar.gz && \
    rm 5.6.tar.gz && \
    cp -a entr-5.6 build-fuzz && \
    cp -a entr-5.6 build-cmplog && \
    cp -a entr-5.6 build-cov && \
    cp -a entr-5.6 build-uftrace && \
    rm -rf entr-5.6

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./configure && \
    make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/entr bin-fuzz && \
    /work/bin-fuzz -h || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN ./configure && \
    AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/entr bin-cmplog && \
    /work/bin-cmplog -h || true

# Copy fuzzing resources
COPY entr/fuzz/dict /work/dict
COPY entr/fuzz/in /work/in
COPY entr/fuzz/fuzz.sh /work/fuzz.sh
COPY entr/fuzz/whatsup.sh /work/whatsup.sh
COPY entr/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY entr/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY entr/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./configure && \
    make CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/entr bin-cov && \
    /work/bin-cov -h || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./configure && \
    make CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    PREFIX=/work/install-uftrace \
    -j$(nproc) && \
    make PREFIX=/work/install-uftrace install

WORKDIR /work
RUN ln -s install-uftrace/bin/entr bin-uftrace && \
    /work/bin-uftrace -h || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
