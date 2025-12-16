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
RUN echo "project: libconfig" > /work/proj && \
    echo "version: 1.7.3" >> /work/proj && \
    echo "source: https://github.com/hyperrealm/libconfig/releases/download/v1.7.3/libconfig-1.7.3.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/hyperrealm/libconfig/releases/download/v1.7.3/libconfig-1.7.3.tar.gz && \
    tar -xzf libconfig-1.7.3.tar.gz && \
    rm libconfig-1.7.3.tar.gz && \
    cp -a libconfig-1.7.3 build-fuzz && \
    cp -a libconfig-1.7.3 build-cmplog && \
    cp -a libconfig-1.7.3 build-cov && \
    cp -a libconfig-1.7.3 build-uftrace && \
    rm -rf libconfig-1.7.3

# Create harness source file
RUN echo '#include <stdio.h>' > /work/harness.c && \
    echo '#include <libconfig.h>' >> /work/harness.c && \
    echo 'int main(int argc, char **argv) {' >> /work/harness.c && \
    echo '    config_t cfg;' >> /work/harness.c && \
    echo '    config_init(&cfg);' >> /work/harness.c && \
    echo '    if(argc > 1) config_read_file(&cfg, argv[1]);' >> /work/harness.c && \
    echo '    config_destroy(&cfg);' >> /work/harness.c && \
    echo '    return 0;' >> /work/harness.c && \
    echo '}' >> /work/harness.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc) && \
    afl-clang-lto -O2 -I./lib /work/harness.c -L./lib/.libs -lconfig -static -Wl,--allow-multiple-definition -o config_parse

WORKDIR /work
RUN ln -s build-fuzz/config_parse bin-fuzz && \
    file /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I./lib /work/harness.c -L./lib/.libs -lconfig -static -Wl,--allow-multiple-definition -o config_parse

WORKDIR /work
RUN ln -s build-cmplog/config_parse bin-cmplog && \
    file /work/bin-cmplog

# Copy fuzzing resources
COPY libconfig/fuzz/dict /work/dict
COPY libconfig/fuzz/in /work/in
COPY libconfig/fuzz/fuzz.sh /work/fuzz.sh
COPY libconfig/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    CXXFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc) && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I./lib /work/harness.c -L./lib/.libs -lconfig -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition -o config_parse

WORKDIR /work
RUN ln -s build-cov/config_parse bin-cov && \
    file /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    CXXFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc) && \
    clang -g -O0 -pg -fno-omit-frame-pointer -I./lib /work/harness.c -L./lib/.libs -lconfig -pg -Wl,--allow-multiple-definition -o config_parse

WORKDIR /work
RUN ln -s build-uftrace/config_parse bin-uftrace && \
    file /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
