FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool pkg-config uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libplist" > /work/proj && \
    echo "version: 2.7.0" >> /work/proj && \
    echo "source: https://github.com/libimobiledevice/libplist/archive/refs/tags/2.7.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libimobiledevice/libplist/archive/refs/tags/2.7.0.tar.gz && \
    tar -xzf 2.7.0.tar.gz && \
    rm 2.7.0.tar.gz && \
    cp -a libplist-2.7.0 build-fuzz && \
    cp -a libplist-2.7.0 build-cmplog && \
    cp -a libplist-2.7.0 build-cov && \
    cp -a libplist-2.7.0 build-uftrace && \
    rm -rf libplist-2.7.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN echo "2.7.0" > .tarball-version && \
    NOCONFIGURE=1 ./autogen.sh && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --without-cython && \
    find . -name Makefile -exec sed -i 's/\(plistutil_LDADD = \)/\1-all-static /' {} \; && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/tools/plistutil bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN echo "2.7.0" > .tarball-version && \
    NOCONFIGURE=1 ./autogen.sh && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --without-cython && \
    find . -name Makefile -exec sed -i 's/\(plistutil_LDADD = \)/\1-all-static /' {} \; && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/tools/plistutil bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY libplist/fuzz/dict /work/dict
COPY libplist/fuzz/in /work/in
COPY libplist/fuzz/fuzz.sh /work/fuzz.sh
COPY libplist/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN echo "2.7.0" > .tarball-version && \
    NOCONFIGURE=1 ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --without-cython && \
    find . -name Makefile -exec sed -i 's/\(plistutil_LDADD = \)/\1-all-static /' {} \; && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/tools/plistutil bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN echo "2.7.0" > .tarball-version && \
    NOCONFIGURE=1 ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace --without-cython && \
    find . -name Makefile -exec sed -i 's/\(plistutil_LDADD = \)/\1-all-static /' {} \; && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/plistutil bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
