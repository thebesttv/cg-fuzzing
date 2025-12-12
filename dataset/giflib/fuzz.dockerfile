FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
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
RUN echo "project: giflib" > /work/proj && \
    echo "version: 5.2.2" >> /work/proj && \
    echo "source: https://sourceforge.net/projects/giflib/files/giflib-5.2.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://sourceforge.net/projects/giflib/files/giflib-5.2.2.tar.gz && \
    tar -xzf giflib-5.2.2.tar.gz && \
    rm giflib-5.2.2.tar.gz && \
    cp -a giflib-5.2.2 build-fuzz && \
    cp -a giflib-5.2.2 build-cmplog && \
    cp -a giflib-5.2.2 build-cov && \
    cp -a giflib-5.2.2 build-uftrace && \
    rm -rf giflib-5.2.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto \
    CFLAGS="-std=gnu99 -Wall -O2" \
    libgif.a && \
    make CC=afl-clang-lto \
    CFLAGS="-std=gnu99 -Wall -O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    giftext \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/giftext bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-std=gnu99 -Wall -O2" \
    libgif.a && \
    AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-std=gnu99 -Wall -O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    giftext

WORKDIR /work
RUN ln -s build-cmplog/giftext bin-cmplog

# Copy fuzzing resources
COPY giflib/fuzz/dict /work/dict
COPY giflib/fuzz/in /work/in
COPY giflib/fuzz/fuzz.sh /work/fuzz.sh
COPY giflib/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang \
    CFLAGS="-std=gnu99 -Wall -g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    libgif.a && \
    make CC=clang \
    CFLAGS="-std=gnu99 -Wall -g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    giftext

WORKDIR /work
RUN ln -s build-cov/giftext bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang \
    CFLAGS="-std=gnu99 -Wall -g -O0 -pg -fno-omit-frame-pointer" \
    libgif.a && \
    make CC=clang \
    CFLAGS="-std=gnu99 -Wall -g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    giftext

WORKDIR /work
RUN ln -s build-uftrace/giftext bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
