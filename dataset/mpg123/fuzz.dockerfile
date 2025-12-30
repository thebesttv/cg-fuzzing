FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget bzip2 uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: mpg123" > /work/proj && \
    echo "version: 1.32.7" >> /work/proj && \
    echo "source: https://downloads.sourceforge.net/project/mpg123/mpg123/1.32.7/mpg123-1.32.7.tar.bz2" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://downloads.sourceforge.net/project/mpg123/mpg123/1.32.7/mpg123-1.32.7.tar.bz2 && \
    tar -xjf mpg123-1.32.7.tar.bz2 && \
    rm mpg123-1.32.7.tar.bz2 && \
    cp -a mpg123-1.32.7 build-fuzz && \
    cp -a mpg123-1.32.7 build-cmplog && \
    cp -a mpg123-1.32.7 build-cov && \
    cp -a mpg123-1.32.7 build-uftrace && \
    rm -rf mpg123-1.32.7

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static --with-audio=dummy && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/mpg123 bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static --with-audio=dummy && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/mpg123 bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY mpg123/fuzz/dict /work/dict
COPY mpg123/fuzz/in /work/in
COPY mpg123/fuzz/fuzz.sh /work/fuzz.sh
COPY mpg123/fuzz/whatsup.sh /work/whatsup.sh
COPY mpg123/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY mpg123/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY mpg123/fuzz/collect-branch.py /work/collect-branch.py
COPY mpg123/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static --with-audio=dummy && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/mpg123 bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --prefix=/work/install-uftrace --disable-shared --enable-static --with-audio=dummy && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/mpg123 bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
