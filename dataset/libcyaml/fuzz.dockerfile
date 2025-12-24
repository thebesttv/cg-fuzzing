FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libyaml-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libcyaml" > /work/proj && \
    echo "version: 1.4.2" >> /work/proj && \
    echo "source: https://api.github.com/repos/tlsa/libcyaml/tarball/v1.4.2" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 -O libcyaml-1.4.2.tar.gz "https://api.github.com/repos/tlsa/libcyaml/tarball/v1.4.2" && \
    tar -xzf libcyaml-1.4.2.tar.gz && \
    mv tlsa-libcyaml-* libcyaml-1.4.2 && \
    rm libcyaml-1.4.2.tar.gz && \
    cp -a libcyaml-1.4.2 build-fuzz && \
    cp -a libcyaml-1.4.2 build-cmplog && \
    cp -a libcyaml-1.4.2 build-cov && \
    cp -a libcyaml-1.4.2 build-uftrace && \
    rm -rf libcyaml-1.4.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    make -j$(nproc)

RUN cd examples/numerical && \
    afl-clang-lto -O2 -I../../include -static -Wl,--allow-multiple-definition \
        -o numerical main.c ../../build/release/libcyaml.a -lyaml

WORKDIR /work
RUN ln -s build-fuzz/examples/numerical/numerical bin-fuzz && \
    /work/bin-fuzz 2>&1 | head -1

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    CFLAGS="-O2" \
    make -j$(nproc)

RUN cd examples/numerical && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I../../include -static -Wl,--allow-multiple-definition \
        -o numerical main.c ../../build/release/libcyaml.a -lyaml

WORKDIR /work
RUN ln -s build-cmplog/examples/numerical/numerical bin-cmplog && \
    /work/bin-cmplog 2>&1 | head -1

# Copy fuzzing resources
COPY libcyaml/fuzz/dict /work/dict
COPY libcyaml/fuzz/in /work/in
COPY libcyaml/fuzz/fuzz.sh /work/fuzz.sh
COPY libcyaml/fuzz/whatsup.sh /work/whatsup.sh
COPY libcyaml/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libcyaml/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libcyaml/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    make -j$(nproc)

RUN cd examples/numerical && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I../../include -static -Wl,--allow-multiple-definition \
        -o numerical main.c ../../build/release/libcyaml.a -lyaml

WORKDIR /work
RUN ln -s build-cov/examples/numerical/numerical bin-cov && \
    /work/bin-cov 2>&1 | head -1 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    make -j$(nproc)

RUN cd examples/numerical && \
    clang -g -O0 -pg -fno-omit-frame-pointer -I../../include -static -Wl,--allow-multiple-definition \
        -o numerical main.c ../../build/release/libcyaml.a -lyaml

WORKDIR /work
RUN ln -s build-uftrace/examples/numerical/numerical bin-uftrace && \
    /work/bin-uftrace 2>&1 | head -1 && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
