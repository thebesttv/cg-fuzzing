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
RUN echo "project: picohttpparser" > /work/proj && \
    echo "version: master" >> /work/proj && \
    echo "source: https://github.com/h2o/picohttpparser/archive/refs/heads/master.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/h2o/picohttpparser/archive/refs/heads/master.tar.gz && \
    tar -xzf master.tar.gz && \
    rm master.tar.gz && \
    cp -a picohttpparser-master build-fuzz && \
    cp -a picohttpparser-master build-cmplog && \
    cp -a picohttpparser-master build-cov && \
    cp -a picohttpparser-master build-uftrace && \
    rm -rf picohttpparser-master

# Copy harness creation script
COPY picohttpparser/create_harness.sh /tmp/create_harness.sh

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN bash /tmp/create_harness.sh && \
    afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o picohttpparser_fuzz \
    fuzz_harness.c picohttpparser.c

WORKDIR /work
RUN ln -s build-fuzz/picohttpparser_fuzz bin-fuzz && \
    echo "Fuzz binary created"

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN bash /tmp/create_harness.sh && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o picohttpparser_fuzz \
    fuzz_harness.c picohttpparser.c

WORKDIR /work
RUN ln -s build-cmplog/picohttpparser_fuzz bin-cmplog && \
    echo "Cmplog binary created"

# Copy fuzzing resources
COPY picohttpparser/fuzz/dict /work/dict
COPY picohttpparser/fuzz/in /work/in
COPY picohttpparser/fuzz/fuzz.sh /work/fuzz.sh
COPY picohttpparser/fuzz/whatsup.sh /work/whatsup.sh
COPY picohttpparser/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY picohttpparser/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY picohttpparser/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN bash /tmp/create_harness.sh && \
    clang \
    -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o picohttpparser_fuzz \
    fuzz_harness.c picohttpparser.c

WORKDIR /work
RUN ln -s build-cov/picohttpparser_fuzz bin-cov && \
    echo "Cov binary created" && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN bash /tmp/create_harness.sh && \
    clang \
    -g -O0 -pg -fno-omit-frame-pointer \
    -I. \
    -pg -Wl,--allow-multiple-definition \
    -o picohttpparser_fuzz \
    fuzz_harness.c picohttpparser.c

WORKDIR /work
RUN ln -s build-uftrace/picohttpparser_fuzz bin-uftrace && \
    echo "Uftrace binary created" && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
