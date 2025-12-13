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
RUN echo "project: mongoose" > /work/proj && \
    echo "version: 7.20" >> /work/proj && \
    echo "source: https://github.com/cesanta/mongoose/archive/refs/tags/7.20.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cesanta/mongoose/archive/refs/tags/7.20.tar.gz && \
    tar -xzf 7.20.tar.gz && \
    rm 7.20.tar.gz && \
    cp -a mongoose-7.20 build-fuzz && \
    cp -a mongoose-7.20 build-cmplog && \
    cp -a mongoose-7.20 build-cov && \
    cp -a mongoose-7.20 build-uftrace && \
    rm -rf mongoose-7.20

# Copy harness source to all build directories
COPY mongoose/fuzz_harness.c /work/build-fuzz/
COPY mongoose/fuzz_harness.c /work/build-cmplog/
COPY mongoose/fuzz_harness.c /work/build-cov/
COPY mongoose/fuzz_harness.c /work/build-uftrace/

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN afl-clang-lto -O2 -DMG_ENABLE_LINES=1 -I. \
    -static -Wl,--allow-multiple-definition \
    -o mongoose_fuzz fuzz_harness.c mongoose.c

WORKDIR /work
RUN ln -s build-fuzz/mongoose_fuzz bin-fuzz && \
    /work/bin-fuzz || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -DMG_ENABLE_LINES=1 -I. \
    -static -Wl,--allow-multiple-definition \
    -o mongoose_fuzz fuzz_harness.c mongoose.c

WORKDIR /work
RUN ln -s build-cmplog/mongoose_fuzz bin-cmplog && \
    /work/bin-cmplog || true

# Copy fuzzing resources
COPY mongoose/fuzz/dict /work/dict
COPY mongoose/fuzz/in /work/in
COPY mongoose/fuzz/fuzz.sh /work/fuzz.sh
COPY mongoose/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -DMG_ENABLE_LINES=1 -I. \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    -o mongoose_fuzz fuzz_harness.c mongoose.c

WORKDIR /work
RUN ln -s build-cov/mongoose_fuzz bin-cov && \
    /work/bin-cov || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN clang -g -O0 -pg -fno-omit-frame-pointer -DMG_ENABLE_LINES=1 -I. \
    -pg -Wl,--allow-multiple-definition \
    -o mongoose_fuzz fuzz_harness.c mongoose.c

WORKDIR /work
RUN ln -s build-uftrace/mongoose_fuzz bin-uftrace && \
    /work/bin-uftrace || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
