FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libunistring-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libidn2" > /work/proj && \
    echo "version: 2.3.8" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/libidn/libidn2-2.3.8.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/libidn/libidn2-2.3.8.tar.gz && \
    tar -xzf libidn2-2.3.8.tar.gz && \
    rm libidn2-2.3.8.tar.gz && \
    cp -a libidn2-2.3.8 build-fuzz && \
    cp -a libidn2-2.3.8 build-cmplog && \
    cp -a libidn2-2.3.8 build-cov && \
    cp -a libidn2-2.3.8 build-uftrace && \
    rm -rf libidn2-2.3.8

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/idn2 bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/idn2 bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY libidn2/fuzz/dict /work/dict
COPY libidn2/fuzz/in /work/in
COPY libidn2/fuzz/fuzz.sh /work/fuzz.sh
COPY libidn2/fuzz/whatsup.sh /work/whatsup.sh
COPY libidn2/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libidn2/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libidn2/fuzz/collect-branch.py /work/collect-branch.py
COPY libidn2/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/idn2 bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/idn2 bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
