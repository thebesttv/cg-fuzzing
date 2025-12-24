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
RUN echo "project: pngcrush" > /work/proj && \
    echo "version: 1.8.13" >> /work/proj && \
    echo "source: https://sourceforge.net/projects/pmt/files/pngcrush/1.8.13/pngcrush-1.8.13.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://sourceforge.net/projects/pmt/files/pngcrush/1.8.13/pngcrush-1.8.13.tar.gz/download -O pngcrush-1.8.13.tar.gz && \
    tar -xzf pngcrush-1.8.13.tar.gz && \
    rm pngcrush-1.8.13.tar.gz && \
    cp -a pngcrush-1.8.13 build-fuzz && \
    cp -a pngcrush-1.8.13 build-cmplog && \
    cp -a pngcrush-1.8.13 build-cov && \
    cp -a pngcrush-1.8.13 build-uftrace && \
    rm -rf pngcrush-1.8.13

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto \
    LD=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/pngcrush bin-fuzz && \
    /work/bin-fuzz -version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    LD=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/pngcrush bin-cmplog && \
    /work/bin-cmplog -version

# Copy fuzzing resources
COPY pngcrush/fuzz/dict /work/dict
COPY pngcrush/fuzz/in /work/in
COPY pngcrush/fuzz/fuzz.sh /work/fuzz.sh
COPY pngcrush/fuzz/whatsup.sh /work/whatsup.sh
COPY pngcrush/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang \
    LD=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/pngcrush bin-cov && \
    /work/bin-cov -version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang \
    LD=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/pngcrush bin-uftrace && \
    /work/bin-uftrace -version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
