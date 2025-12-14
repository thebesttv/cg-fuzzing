FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: ssdeep" > /work/proj && \
    echo "version: 2.14.1" >> /work/proj && \
    echo "source: https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget "https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz" && \
    tar -xzf ssdeep-2.14.1.tar.gz && \
    rm ssdeep-2.14.1.tar.gz && \
    cp -a ssdeep-2.14.1 build-fuzz && \
    cp -a ssdeep-2.14.1 build-cmplog && \
    cp -a ssdeep-2.14.1 build-cov && \
    cp -a ssdeep-2.14.1 build-uftrace && \
    rm -rf ssdeep-2.14.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make CC=afl-clang-lto CXX=afl-clang-lto++ LDFLAGS="-all-static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/ssdeep bin-fuzz && \
    /work/bin-fuzz -V

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto CXX=afl-clang-lto++ LDFLAGS="-all-static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/ssdeep bin-cmplog && \
    /work/bin-cmplog -V

# Copy fuzzing resources
COPY ssdeep/fuzz/dict /work/dict
COPY ssdeep/fuzz/in /work/in
COPY ssdeep/fuzz/fuzz.sh /work/fuzz.sh
COPY ssdeep/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    CXXFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make LDFLAGS="-all-static -fprofile-instr-generate -fcoverage-mapping -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/ssdeep bin-cov && \
    /work/bin-cov -V && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    CXXFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace --disable-shared --enable-static && \
    make LDFLAGS="-all-static -pg -Wl,--allow-multiple-definition" -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/ssdeep bin-uftrace && \
    /work/bin-uftrace -V && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
