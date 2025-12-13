FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: mandoc" > /work/proj && \
    echo "version: 1.14.6" >> /work/proj && \
    echo "source: https://mandoc.bsd.lv/snapshots/mandoc.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://mandoc.bsd.lv/snapshots/mandoc.tar.gz && \
    tar -xzf mandoc.tar.gz && \
    rm mandoc.tar.gz && \
    cp -a mandoc-1.14.6 build-fuzz && \
    cp -a mandoc-1.14.6 build-cmplog && \
    cp -a mandoc-1.14.6 build-cov && \
    cp -a mandoc-1.14.6 build-uftrace && \
    rm -rf mandoc-1.14.6

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN printf 'CC=afl-clang-lto\nCFLAGS="-O2"\nLDFLAGS="-static -Wl,--allow-multiple-definition"\nSTATIC=-static\n' > configure.local && \
    ./configure && \
    make mandoc -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/mandoc bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN printf 'CC=afl-clang-lto\nCFLAGS="-O2"\nLDFLAGS="-static -Wl,--allow-multiple-definition"\nSTATIC=-static\n' > configure.local && \
    AFL_LLVM_CMPLOG=1 ./configure && \
    AFL_LLVM_CMPLOG=1 make mandoc -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/mandoc bin-cmplog

# Copy fuzzing resources
COPY mandoc/fuzz/dict /work/dict
COPY mandoc/fuzz/in /work/in
COPY mandoc/fuzz/fuzz.sh /work/fuzz.sh
COPY mandoc/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN printf 'CC=clang\nCFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping"\nLDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition"\nSTATIC=-static\n' > configure.local && \
    ./configure && \
    make mandoc -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/mandoc bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN printf 'CC=clang\nCFLAGS="-g -O0 -pg -fno-omit-frame-pointer"\nLDFLAGS="-pg -Wl,--allow-multiple-definition"\nSTATIC=-static\n' > configure.local && \
    ./configure && \
    make mandoc -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/mandoc bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
