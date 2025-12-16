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
RUN echo "project: lighttpd" > /work/proj && \
    echo "version: 1.4.82" >> /work/proj && \
    echo "source: https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.82.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.82.tar.gz && \
    tar -xzf lighttpd-1.4.82.tar.gz && \
    rm lighttpd-1.4.82.tar.gz && \
    cp -a lighttpd-1.4.82 build-fuzz && \
    cp -a lighttpd-1.4.82 build-cmplog && \
    cp -a lighttpd-1.4.82 build-cov && \
    cp -a lighttpd-1.4.82 build-uftrace && \
    rm -rf lighttpd-1.4.82

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared \
                --without-bzip2 \
                --without-zlib \
                --without-pcre2 && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/lighttpd bin-fuzz && \
    /work/bin-fuzz -v

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared \
                --without-bzip2 \
                --without-zlib \
                --without-pcre2 && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/lighttpd bin-cmplog && \
    /work/bin-cmplog -v

# Copy fuzzing resources
COPY lighttpd/fuzz/dict /work/dict
COPY lighttpd/fuzz/in /work/in
COPY lighttpd/fuzz/fuzz.sh /work/fuzz.sh
COPY lighttpd/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared \
                --without-bzip2 \
                --without-zlib \
                --without-pcre2 && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/lighttpd bin-cov && \
    /work/bin-cov -v && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared \
                --without-bzip2 \
                --without-zlib \
                --without-pcre2 \
                --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/sbin/lighttpd bin-uftrace && \
    /work/bin-uftrace -v && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
