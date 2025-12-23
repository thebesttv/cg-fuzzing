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
RUN echo "project: enscript" > /work/proj && \
    echo "version: 1.6.6" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/enscript/enscript-1.6.6.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/enscript/enscript-1.6.6.tar.gz && \
    tar -xzf enscript-1.6.6.tar.gz && \
    rm enscript-1.6.6.tar.gz && \
    cp -a enscript-1.6.6 build-fuzz && \
    cp -a enscript-1.6.6 build-cmplog && \
    cp -a enscript-1.6.6 build-cov && \
    cp -a enscript-1.6.6 build-uftrace && \
    rm -rf enscript-1.6.6

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/enscript bin-fuzz && \
    /work/bin-fuzz --version || true

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
RUN ln -s build-cmplog/src/enscript bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY enscript/fuzz/dict /work/dict
COPY enscript/fuzz/in /work/in
COPY enscript/fuzz/fuzz.sh /work/fuzz.sh
COPY enscript/fuzz/whatsup.sh /work/whatsup.sh
COPY enscript/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/enscript bin-cov && \
    /work/bin-cov --version || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/enscript bin-uftrace && \
    rm -f gmon.out

# Set environment for enscript to find its config
ENV ENSCRIPT_LIBRARY=/work/install-uftrace/share/enscript

# Verify all binaries work
RUN /work/bin-fuzz --version && \
    /work/bin-cmplog --version && \
    /work/bin-cov --version && \
    /work/bin-uftrace --version

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
