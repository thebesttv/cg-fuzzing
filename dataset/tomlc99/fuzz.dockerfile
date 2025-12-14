FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget unzip uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: tomlc99" > /work/proj && \
    echo "version: master" >> /work/proj && \
    echo "source: https://github.com/cktan/tomlc99/archive/refs/heads/master.zip" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cktan/tomlc99/archive/refs/heads/master.zip && \
    unzip master.zip && \
    rm master.zip && \
    cp -a tomlc99-master build-fuzz && \
    cp -a tomlc99-master build-cmplog && \
    cp -a tomlc99-master build-cov && \
    cp -a tomlc99-master build-uftrace && \
    rm -rf tomlc99-master

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    make -j$(nproc)

RUN afl-clang-lto -O2 -o toml_cat toml_cat.c libtoml.a \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-fuzz/toml_cat bin-fuzz && \
    /work/bin-fuzz /work/build-fuzz/sample.toml

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc)

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -o toml_cat toml_cat.c libtoml.a \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cmplog/toml_cat bin-cmplog && \
    /work/bin-cmplog /work/build-cmplog/sample.toml

# Copy fuzzing resources
COPY tomlc99/fuzz/dict /work/dict
COPY tomlc99/fuzz/in /work/in
COPY tomlc99/fuzz/fuzz.sh /work/fuzz.sh
COPY tomlc99/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    make -j$(nproc)

RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -o toml_cat toml_cat.c libtoml.a \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cov/toml_cat bin-cov && \
    /work/bin-cov /work/build-cov/sample.toml && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    make -j$(nproc)

RUN clang -g -O0 -pg -fno-omit-frame-pointer \
    -o toml_cat toml_cat.c libtoml.a \
    -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-uftrace/toml_cat bin-uftrace && \
    /work/bin-uftrace /work/build-uftrace/sample.toml && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
