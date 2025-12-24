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
RUN echo "project: gawk" > /work/proj && \
    echo "version: 5.3.2" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/gawk/gawk-5.3.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/gawk/gawk-5.3.2.tar.gz && \
    tar -xzf gawk-5.3.2.tar.gz && \
    rm gawk-5.3.2.tar.gz && \
    cp -a gawk-5.3.2 build-fuzz && \
    cp -a gawk-5.3.2 build-cmplog && \
    cp -a gawk-5.3.2 build-cov && \
    cp -a gawk-5.3.2 build-uftrace && \
    rm -rf gawk-5.3.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --disable-extensions && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/gawk bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --disable-extensions && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/gawk bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY gawk/fuzz/dict /work/dict
COPY gawk/fuzz/in /work/in
COPY gawk/fuzz/fuzz.sh /work/fuzz.sh
COPY gawk/fuzz/whatsup.sh /work/whatsup.sh
COPY gawk/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY gawk/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY gawk/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --disable-extensions && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/gawk bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --disable-extensions && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/gawk bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
