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
RUN echo "project: unifdef" > /work/proj && \
    echo "version: 2.12" >> /work/proj && \
    echo "source: https://ftp2.osuosl.org/pub/blfs/12.4/u/unifdef-2.12.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp2.osuosl.org/pub/blfs/12.4/u/unifdef-2.12.tar.gz && \
    tar -xzf unifdef-2.12.tar.gz && \
    rm unifdef-2.12.tar.gz && \
    cp -a unifdef-2.12 build-fuzz && \
    cp -a unifdef-2.12 build-cmplog && \
    cp -a unifdef-2.12 build-cov && \
    cp -a unifdef-2.12 build-uftrace && \
    rm -rf unifdef-2.12

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-fuzz/unifdef bin-fuzz && \
    /work/bin-fuzz --version || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-cmplog/unifdef bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY unifdef/fuzz/dict /work/dict
COPY unifdef/fuzz/in /work/in
COPY unifdef/fuzz/fuzz.sh /work/fuzz.sh
COPY unifdef/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-cov/unifdef bin-cov && \
    /work/bin-cov --version || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition"

# Install to prefix
RUN make install prefix=/work/install-uftrace

WORKDIR /work
RUN ln -s install-uftrace/bin/unifdef bin-uftrace && \
    /work/bin-uftrace --version || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
