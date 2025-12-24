FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool gettext autopoint pkg-config libncurses-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: procps" > /work/proj && \
    echo "version: 4.0.4" >> /work/proj && \
    echo "source: https://gitlab.com/procps-ng/procps/-/archive/v4.0.4/procps-v4.0.4.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://gitlab.com/procps-ng/procps/-/archive/v4.0.4/procps-v4.0.4.tar.gz && \
    tar -xzf procps-v4.0.4.tar.gz && \
    rm procps-v4.0.4.tar.gz && \
    cp -a procps-v4.0.4 build-fuzz && \
    cp -a procps-v4.0.4 build-cmplog && \
    cp -a procps-v4.0.4 build-cov && \
    cp -a procps-v4.0.4 build-uftrace && \
    rm -rf procps-v4.0.4

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-nls && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/ps/pscommand bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --disable-nls && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/ps/pscommand bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY procps/fuzz/dict /work/dict
COPY procps/fuzz/in /work/in
COPY procps/fuzz/fuzz.sh /work/fuzz.sh
COPY procps/fuzz/whatsup.sh /work/whatsup.sh
COPY procps/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY procps/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY procps/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-nls && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/ps/pscommand bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-nls && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/src/ps/pscommand bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
