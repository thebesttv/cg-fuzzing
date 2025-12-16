FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool flex bison \
        libgd-dev libexpat1-dev zlib1g-dev libpng-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: graphviz" > /work/proj && \
    echo "version: 12.2.1" >> /work/proj && \
    echo "source: https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/12.2.1/graphviz-12.2.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/12.2.1/graphviz-12.2.1.tar.gz && \
    tar -xzf graphviz-12.2.1.tar.gz && \
    rm graphviz-12.2.1.tar.gz && \
    cp -a graphviz-12.2.1 build-fuzz && \
    cp -a graphviz-12.2.1 build-cmplog && \
    cp -a graphviz-12.2.1 build-cov && \
    cp -a graphviz-12.2.1 build-uftrace && \
    rm -rf graphviz-12.2.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --without-x \
        --without-qt \
        --without-gtk \
        --without-glade \
        --disable-ltdl \
        --enable-ltdl-install=no && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/cmd/dot/dot_static bin-fuzz && \
    /work/bin-fuzz -V

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --without-x \
        --without-qt \
        --without-gtk \
        --without-glade \
        --disable-ltdl \
        --enable-ltdl-install=no && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/cmd/dot/dot_static bin-cmplog && \
    /work/bin-cmplog -V

# Copy fuzzing resources
COPY graphviz/fuzz/dict /work/dict
COPY graphviz/fuzz/in /work/in
COPY graphviz/fuzz/fuzz.sh /work/fuzz.sh
COPY graphviz/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --without-x \
        --without-qt \
        --without-gtk \
        --without-glade \
        --disable-ltdl \
        --enable-ltdl-install=no && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/cmd/dot/dot_static bin-cov && \
    /work/bin-cov -V && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --without-x \
        --without-qt \
        --without-gtk \
        --without-glade \
        --disable-ltdl \
        --enable-ltdl-install=no && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/cmd/dot/dot_static bin-uftrace && \
    /work/bin-uftrace -V && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
