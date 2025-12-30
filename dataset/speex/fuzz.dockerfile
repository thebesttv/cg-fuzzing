FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool pkg-config libogg-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: speex" > /work/proj && \
    echo "version: 1.2.1" >> /work/proj && \
    echo "source: https://github.com/xiph/speex/archive/refs/tags/Speex-1.2.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/speex/archive/refs/tags/Speex-1.2.1.tar.gz && \
    tar -xzf Speex-1.2.1.tar.gz && \
    rm Speex-1.2.1.tar.gz && \
    cp -a speex-Speex-1.2.1 build-fuzz && \
    cp -a speex-Speex-1.2.1 build-cmplog && \
    cp -a speex-Speex-1.2.1 build-cov && \
    cp -a speex-Speex-1.2.1 build-uftrace && \
    rm -rf speex-Speex-1.2.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-oggtest --disable-binaries && \
    make -j$(nproc)

# Build speexdec with afl-clang-lto
RUN cd src && \
    afl-clang-lto -O2 -I../include -I.. -DHAVE_CONFIG_H -Wl,--allow-multiple-definition \
        speexdec.c getopt.c getopt1.c wav_io.c \
        -L../libspeex/.libs -lspeex -logg -lm \
        -o speexdec

WORKDIR /work
RUN ln -s build-fuzz/src/speexdec bin-fuzz && \
    /work/bin-fuzz --version || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --disable-oggtest --disable-binaries && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build speexdec with CMPLOG
RUN cd src && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I../include -I.. -DHAVE_CONFIG_H -Wl,--allow-multiple-definition \
        speexdec.c getopt.c getopt1.c wav_io.c \
        -L../libspeex/.libs -lspeex -logg -lm \
        -o speexdec

WORKDIR /work
RUN ln -s build-cmplog/src/speexdec bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY speex/fuzz/dict /work/dict
COPY speex/fuzz/in /work/in
COPY speex/fuzz/fuzz.sh /work/fuzz.sh
COPY speex/fuzz/whatsup.sh /work/whatsup.sh
COPY speex/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY speex/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY speex/fuzz/collect-branch.py /work/collect-branch.py
COPY speex/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY speex/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-oggtest --disable-binaries && \
    make -j$(nproc)

# Build speexdec with coverage
RUN cd src && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I../include -I.. -DHAVE_CONFIG_H \
        -fprofile-instr-generate -fcoverage-mapping -Wl,--allow-multiple-definition \
        speexdec.c getopt.c getopt1.c wav_io.c \
        -L../libspeex/.libs -lspeex -logg -lm \
        -o speexdec

WORKDIR /work
RUN ln -s build-cov/src/speexdec bin-cov && \
    /work/bin-cov --version || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-oggtest --disable-binaries && \
    make -j$(nproc)

# Build speexdec with uftrace
RUN cd src && \
    clang -g -O0 -pg -fno-omit-frame-pointer -I../include -I.. -DHAVE_CONFIG_H \
        -pg -Wl,--allow-multiple-definition \
        speexdec.c getopt.c getopt1.c wav_io.c \
        -L../libspeex/.libs -lspeex -logg -lm \
        -o speexdec

WORKDIR /work
RUN ln -s build-uftrace/src/speexdec bin-uftrace && \
    /work/bin-uftrace --version || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
