FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libssl-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: iperf3" > /work/proj && \
    echo "version: 3.17.1" >> /work/proj && \
    echo "source: https://github.com/esnet/iperf/releases/download/3.17.1/iperf-3.17.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/esnet/iperf/releases/download/3.17.1/iperf-3.17.1.tar.gz && \
    tar -xzf iperf-3.17.1.tar.gz && \
    rm iperf-3.17.1.tar.gz && \
    cp -a iperf-3.17.1 build-fuzz && \
    cp -a iperf-3.17.1 build-cmplog && \
    cp -a iperf-3.17.1 build-cov && \
    cp -a iperf-3.17.1 build-uftrace && \
    rm -rf iperf-3.17.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/iperf3 bin-fuzz && \
    /work/bin-fuzz --version

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
RUN ln -s build-cmplog/src/iperf3 bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY iperf3/fuzz/dict /work/dict
COPY iperf3/fuzz/in /work/in
COPY iperf3/fuzz/fuzz.sh /work/fuzz.sh
COPY iperf3/fuzz/whatsup.sh /work/whatsup.sh
COPY iperf3/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/iperf3 bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/src/iperf3 bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
