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
RUN echo "project: libyaml" > /work/proj && \
    echo "version: 0.2.5" >> /work/proj && \
    echo "source: https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz && \
    tar -xzf yaml-0.2.5.tar.gz && \
    rm yaml-0.2.5.tar.gz && \
    cp -a yaml-0.2.5 build-fuzz && \
    cp -a yaml-0.2.5 build-cmplog && \
    cp -a yaml-0.2.5 build-cov && \
    cp -a yaml-0.2.5 build-uftrace && \
    rm -rf yaml-0.2.5

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/tests/run-parser bin-fuzz && \
    echo "test: 1" | /work/bin-fuzz /dev/stdin

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
RUN ln -s build-cmplog/tests/run-parser bin-cmplog && \
    echo "test: 1" | /work/bin-cmplog /dev/stdin

# Copy fuzzing resources
COPY libyaml/fuzz/dict /work/dict
COPY libyaml/fuzz/in /work/in
COPY libyaml/fuzz/fuzz.sh /work/fuzz.sh
COPY libyaml/fuzz/whatsup.sh /work/whatsup.sh
COPY libyaml/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libyaml/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libyaml/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/tests/run-parser bin-cov && \
    echo "test: 1" | /work/bin-cov /dev/stdin && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install && \
    mkdir -p /work/install-uftrace/bin && \
    cp tests/run-parser /work/install-uftrace/bin/

WORKDIR /work
RUN ln -s install-uftrace/bin/run-parser bin-uftrace && \
    echo "test: 1" | /work/bin-uftrace /dev/stdin && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
