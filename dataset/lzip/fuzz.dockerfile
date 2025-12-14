FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
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
RUN echo "project: lzip" > /work/proj && \
    echo "version: 1.15" >> /work/proj && \
    echo "source: http://download.savannah.gnu.org/releases/lzip/lzip-1.15.tar.gz" >> /work/proj

# Copy source once and extract to multiple build directories
COPY lzip/lzip-1.15.tar.gz /work/
RUN tar -xzf lzip-1.15.tar.gz && \
    rm lzip-1.15.tar.gz && \
    cp -a lzip-1.15 build-fuzz && \
    cp -a lzip-1.15 build-cmplog && \
    cp -a lzip-1.15 build-cov && \
    cp -a lzip-1.15 build-uftrace && \
    rm -rf lzip-1.15

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure && \
    make CXX=afl-clang-lto++ -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/lzip bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure && \
    AFL_LLVM_CMPLOG=1 make CXX=afl-clang-lto++ -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/lzip bin-cmplog

# Copy fuzzing resources
COPY lzip/fuzz/dict /work/dict
COPY lzip/fuzz/in /work/in
COPY lzip/fuzz/fuzz.sh /work/fuzz.sh
COPY lzip/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    CXXFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure && \
    make CXX=clang++ -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/lzip bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    CXXFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace && \
    make CXX=clang++ -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/lzip bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
