FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget flex bison libssl-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: tcpdump" > /work/proj && \
    echo "version: 4.99.5 (with libpcap 1.10.5)" >> /work/proj && \
    echo "source: https://www.tcpdump.org/release/tcpdump-4.99.5.tar.gz" >> /work/proj

# Download sources once
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.tcpdump.org/release/libpcap-1.10.5.tar.gz && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.tcpdump.org/release/tcpdump-4.99.5.tar.gz

# Extract once and copy to multiple build directories
RUN tar -xzf libpcap-1.10.5.tar.gz && \
    tar -xzf tcpdump-4.99.5.tar.gz && \
    cp -a libpcap-1.10.5 libpcap-fuzz && \
    cp -a libpcap-1.10.5 libpcap-cmplog && \
    cp -a libpcap-1.10.5 libpcap-cov && \
    cp -a libpcap-1.10.5 libpcap-uftrace && \
    cp -a tcpdump-4.99.5 build-fuzz && \
    cp -a tcpdump-4.99.5 build-cmplog && \
    cp -a tcpdump-4.99.5 build-cov && \
    cp -a tcpdump-4.99.5 build-uftrace && \
    rm -rf libpcap-1.10.5 tcpdump-4.99.5 libpcap-1.10.5.tar.gz tcpdump-4.99.5.tar.gz

# Build libpcap for fuzz
WORKDIR /work/libpcap-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc) && \
    make install

# Build tcpdump with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/tcpdump bin-fuzz && \
    /work/bin-fuzz --version

# Build libpcap for cmplog
WORKDIR /work/libpcap-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    make install

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/tcpdump bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY tcpdump/fuzz/dict /work/dict
COPY tcpdump/fuzz/in /work/in
COPY tcpdump/fuzz/fuzz.sh /work/fuzz.sh
COPY tcpdump/fuzz/whatsup.sh /work/whatsup.sh
COPY tcpdump/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY tcpdump/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY tcpdump/fuzz/collect-branch.py /work/collect-branch.py

# Build libpcap for cov
WORKDIR /work/libpcap-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc) && \
    make install

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/tcpdump bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build libpcap for uftrace
WORKDIR /work/libpcap-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc) && \
    make install

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/tcpdump bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
