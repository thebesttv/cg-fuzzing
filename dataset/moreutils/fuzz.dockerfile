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
RUN echo "project: moreutils" > /work/proj && \
    echo "version: 0.69" >> /work/proj && \
    echo "source: https://git.joeyh.name/index.cgi/moreutils.git/snapshot/moreutils-0.69.tar.gz" >> /work/proj

# Copy source once and extract to multiple build directories
COPY moreutils/moreutils-0.69.tar.gz /work/
RUN tar -xzf moreutils-0.69.tar.gz && \
    rm moreutils-0.69.tar.gz && \
    cp -a moreutils-0.69 build-fuzz && \
    cp -a moreutils-0.69 build-cmplog && \
    cp -a moreutils-0.69 build-cov && \
    cp -a moreutils-0.69 build-uftrace && \
    rm -rf moreutils-0.69

# Build fuzz binary with afl-clang-lto (focus on pee)
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make pee -j$(nproc) || true

WORKDIR /work
RUN ln -s build-fuzz/pee bin-fuzz && \
    test -x /work/bin-fuzz && echo "bin-fuzz created successfully"

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make pee -j$(nproc) || true

WORKDIR /work
RUN ln -s build-cmplog/pee bin-cmplog && \
    test -x /work/bin-cmplog && echo "bin-cmplog created successfully"

# Copy fuzzing resources
COPY moreutils/fuzz/dict /work/dict
COPY moreutils/fuzz/in /work/in
COPY moreutils/fuzz/fuzz.sh /work/fuzz.sh
COPY moreutils/fuzz/whatsup.sh /work/whatsup.sh
COPY moreutils/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY moreutils/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY moreutils/fuzz/collect-branch.py /work/collect-branch.py
COPY moreutils/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY moreutils/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    make pee -j$(nproc) || true

WORKDIR /work
RUN ln -s build-cov/pee bin-cov && \
    test -x /work/bin-cov && echo "bin-cov created successfully" && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make pee -j$(nproc) || true

WORKDIR /work
RUN ln -s build-uftrace/pee bin-uftrace && \
    test -x /work/bin-uftrace && echo "bin-uftrace created successfully" && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
