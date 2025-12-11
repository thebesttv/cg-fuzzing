FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux && \
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
RUN echo "project: quickjs" > /work/proj && \
    echo "version: 2024-01-13" >> /work/proj && \
    echo "source: https://bellard.org/quickjs/quickjs-2024-01-13.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://bellard.org/quickjs/quickjs-2024-01-13.tar.xz && \
    tar -xJf quickjs-2024-01-13.tar.xz && \
    rm quickjs-2024-01-13.tar.xz && \
    cp -r quickjs-2024-01-13 build-fuzz && \
    cp -r quickjs-2024-01-13 build-cmplog && \
    cp -r quickjs-2024-01-13 build-cov && \
    cp -r quickjs-2024-01-13 build-uftrace && \
    rm -rf quickjs-2024-01-13

# Build quickjs with afl-clang-lto for fuzzing
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto \
    CFLAGS="-O2 -D_GNU_SOURCE -DCONFIG_VERSION=\\\"2024-01-13\\\"" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    CONFIG_LTO= \
    CONFIG_BIGNUM= \
    qjs \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/qjs bin-fuzz && \
    /work/bin-fuzz --help || true

# Build quickjs with afl-clang-lto + CMPLOG for cmplog
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2 -D_GNU_SOURCE -DCONFIG_VERSION=\\\"2024-01-13\\\"" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    CONFIG_LTO= \
    CONFIG_BIGNUM= \
    qjs \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/qjs bin-cmplog && \
    /work/bin-cmplog --help || true

# Copy fuzzing resources
COPY quickjs/fuzz/dict /work/dict
COPY quickjs/fuzz/in /work/in
COPY quickjs/fuzz/fuzz.sh /work/fuzz.sh
COPY quickjs/fuzz/whatsup.sh /work/whatsup.sh

# Build quickjs with llvm-cov instrumentation for cov
WORKDIR /work/build-cov
RUN make CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -D_GNU_SOURCE -DCONFIG_VERSION=\\\"2024-01-13\\\"" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    CONFIG_LTO= \
    CONFIG_BIGNUM= \
    qjs \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/qjs bin-cov && \
    /work/bin-cov --help || true && \
    rm -f *.profraw

# Build quickjs with profiling instrumentation for uftrace
WORKDIR /work/build-uftrace
RUN make CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer -D_GNU_SOURCE -DCONFIG_VERSION=\\\"2024-01-13\\\"" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    CONFIG_LTO= \
    CONFIG_BIGNUM= \
    qjs \
    -j$(nproc)

RUN mkdir -p /work/install-uftrace/bin && \
    cp qjs /work/install-uftrace/bin/

WORKDIR /work
RUN ln -s install-uftrace/bin/qjs bin-uftrace && \
    /work/bin-uftrace --help || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
