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
RUN echo "project: scdoc" > /work/proj && \
    echo "version: 1.11.3" >> /work/proj && \
    echo "source: https://git.sr.ht/~sircmpwn/scdoc/archive/1.11.3.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://git.sr.ht/~sircmpwn/scdoc/archive/1.11.3.tar.gz && \
    tar -xzf 1.11.3.tar.gz && \
    rm 1.11.3.tar.gz && \
    cp -a scdoc-1.11.3 build-fuzz && \
    cp -a scdoc-1.11.3 build-cmplog && \
    cp -a scdoc-1.11.3 build-cov && \
    cp -a scdoc-1.11.3 build-uftrace && \
    rm -rf scdoc-1.11.3

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/scdoc bin-fuzz && \
    test -x /work/bin-fuzz && echo "bin-fuzz created successfully"

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/scdoc bin-cmplog && \
    test -x /work/bin-cmplog && echo "bin-cmplog created successfully"

# Copy fuzzing resources
COPY scdoc/fuzz/dict /work/dict
COPY scdoc/fuzz/in /work/in
COPY scdoc/fuzz/fuzz.sh /work/fuzz.sh
COPY scdoc/fuzz/whatsup.sh /work/whatsup.sh
COPY scdoc/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/scdoc bin-cov && \
    test -x /work/bin-cov && echo "bin-cov created successfully" && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/scdoc bin-uftrace && \
    test -x /work/bin-uftrace && echo "bin-uftrace created successfully" && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
