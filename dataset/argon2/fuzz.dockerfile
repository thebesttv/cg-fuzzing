FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux && \
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
RUN echo "project: argon2" > /work/proj && \
    echo "version: 20190702" >> /work/proj && \
    echo "source: https://github.com/P-H-C/phc-winner-argon2/archive/refs/tags/20190702.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/P-H-C/phc-winner-argon2/archive/refs/tags/20190702.tar.gz && \
    tar -xzf 20190702.tar.gz && \
    rm 20190702.tar.gz && \
    cp -a phc-winner-argon2-20190702 build-fuzz && \
    cp -a phc-winner-argon2-20190702 build-cmplog && \
    cp -a phc-winner-argon2-20190702 build-cov && \
    cp -a phc-winner-argon2-20190702 build-uftrace && \
    rm -rf phc-winner-argon2-20190702

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -pthread -Iinclude -Isrc" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -pthread" \
    argon2 \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/argon2 bin-fuzz && \
    echo "test" | /work/bin-fuzz password -t 1 -m 10 -p 1 -l 16 -e || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN make CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -pthread -Iinclude -Isrc" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -pthread" \
    AFL_LLVM_CMPLOG=1 \
    argon2 \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/argon2 bin-cmplog && \
    echo "test" | /work/bin-cmplog password -t 1 -m 10 -p 1 -l 16 -e || true

# Copy fuzzing resources
COPY argon2/fuzz/dict /work/dict
COPY argon2/fuzz/in /work/in
COPY argon2/fuzz/fuzz.sh /work/fuzz.sh
COPY argon2/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -pthread -Iinclude -Isrc" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition -pthread" \
    argon2 \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/argon2 bin-cov && \
    echo "test" | /work/bin-cov password -t 1 -m 10 -p 1 -l 16 -e || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer -pthread -Iinclude -Isrc" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition -pthread" \
    argon2 \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/argon2 bin-uftrace && \
    echo "test" | /work/bin-uftrace password -t 1 -m 10 -p 1 -l 16 -e || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
