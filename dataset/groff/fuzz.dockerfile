FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget m4 uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: groff" > /work/proj && \
    echo "version: 1.23.0" >> /work/proj && \
    echo "source: https://ftp.gnu.org/gnu/groff/groff-1.23.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/groff/groff-1.23.0.tar.gz && \
    tar -xzf groff-1.23.0.tar.gz && \
    rm groff-1.23.0.tar.gz && \
    cp -a groff-1.23.0 build-fuzz && \
    cp -a groff-1.23.0 build-cmplog && \
    cp -a groff-1.23.0 build-cov && \
    cp -a groff-1.23.0 build-uftrace && \
    rm -rf groff-1.23.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --prefix=/work/install-fuzz && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-fuzz/bin/groff bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --prefix=/work/install-cmplog && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-cmplog/bin/groff bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY groff/fuzz/dict /work/dict
COPY groff/fuzz/in /work/in
COPY groff/fuzz/fuzz.sh /work/fuzz.sh
COPY groff/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    CXXFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --prefix=/work/install-cov && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-cov/bin/groff bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    CXXFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/groff bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
