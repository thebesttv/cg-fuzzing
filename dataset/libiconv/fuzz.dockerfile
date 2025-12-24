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
RUN echo "project: libiconv" > /work/proj && \
    echo "version: 1.18" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/libiconv/libiconv-1.18.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/libiconv/libiconv-1.18.tar.gz && \
    tar -xzf libiconv-1.18.tar.gz && \
    rm libiconv-1.18.tar.gz && \
    cp -a libiconv-1.18 build-fuzz && \
    cp -a libiconv-1.18 build-cmplog && \
    cp -a libiconv-1.18 build-cov && \
    cp -a libiconv-1.18 build-uftrace && \
    rm -rf libiconv-1.18

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/iconv_no_i18n bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/iconv_no_i18n bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY libiconv/fuzz/dict /work/dict
COPY libiconv/fuzz/in /work/in
COPY libiconv/fuzz/fuzz.sh /work/fuzz.sh
COPY libiconv/fuzz/whatsup.sh /work/whatsup.sh
COPY libiconv/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libiconv/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libiconv/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/iconv_no_i18n bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/src/iconv_no_i18n bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
