FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: qbe" > /work/proj && \
    echo "version: 1.2" >> /work/proj && \
    echo "source: https://c9x.me/compile/release/qbe-1.2.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://c9x.me/compile/release/qbe-1.2.tar.xz && \
    tar -xJf qbe-1.2.tar.xz && \
    rm qbe-1.2.tar.xz && \
    cp -a qbe-1.2 build-fuzz && \
    cp -a qbe-1.2 build-cmplog && \
    cp -a qbe-1.2 build-cov && \
    cp -a qbe-1.2 build-uftrace && \
    rm -rf qbe-1.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/qbe bin-fuzz && \
    /work/bin-fuzz -h || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/qbe bin-cmplog && \
    /work/bin-cmplog -h || true

# Copy fuzzing resources
COPY qbe/fuzz/dict /work/dict
COPY qbe/fuzz/in /work/in
COPY qbe/fuzz/fuzz.sh /work/fuzz.sh
COPY qbe/fuzz/whatsup.sh /work/whatsup.sh
COPY qbe/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang \
    CFLAGS="-std=c99 -g -O0 -Wall -Wextra -Wpedantic -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/qbe bin-cov && \
    /work/bin-cov -h || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang \
    CFLAGS="-std=c99 -g -O0 -Wall -Wextra -Wpedantic -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/qbe bin-uftrace && \
    /work/bin-uftrace -h || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
