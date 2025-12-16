FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake gettext libncurses-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: minicom" > /work/proj && \
    echo "version: 2.9" >> /work/proj && \
    echo "source: https://salsa.debian.org/minicom-team/minicom/-/archive/2.9/minicom-2.9.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://salsa.debian.org/minicom-team/minicom/-/archive/2.9/minicom-2.9.tar.gz && \
    tar -xzf minicom-2.9.tar.gz && \
    rm minicom-2.9.tar.gz && \
    cp -a minicom-2.9 build-fuzz && \
    cp -a minicom-2.9 build-cmplog && \
    cp -a minicom-2.9 build-cov && \
    cp -a minicom-2.9 build-uftrace && \
    rm -rf minicom-2.9

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/minicom bin-fuzz && \
    /work/bin-fuzz --version || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/minicom bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY minicom/fuzz/dict /work/dict
COPY minicom/fuzz/in /work/in
COPY minicom/fuzz/fuzz.sh /work/fuzz.sh
COPY minicom/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/minicom bin-cov && \
    /work/bin-cov --version || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/minicom bin-uftrace && \
    /work/bin-uftrace --version || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
