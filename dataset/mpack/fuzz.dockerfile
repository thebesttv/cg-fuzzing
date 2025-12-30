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
RUN echo "project: mpack" > /work/proj && \
    echo "version: 1.1.1" >> /work/proj && \
    echo "source: https://github.com/ludocode/mpack/releases/download/v1.1.1/mpack-amalgamation-1.1.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ludocode/mpack/releases/download/v1.1.1/mpack-amalgamation-1.1.1.tar.gz && \
    tar -xzf mpack-amalgamation-1.1.1.tar.gz && \
    rm mpack-amalgamation-1.1.1.tar.gz && \
    cp -a mpack-amalgamation-1.1.1 build-fuzz && \
    cp -a mpack-amalgamation-1.1.1 build-cmplog && \
    cp -a mpack-amalgamation-1.1.1 build-cov && \
    cp -a mpack-amalgamation-1.1.1 build-uftrace && \
    rm -rf mpack-amalgamation-1.1.1

# Copy harness source to all build directories
COPY mpack/fuzz_mpack.c /work/build-fuzz/
COPY mpack/fuzz_mpack.c /work/build-cmplog/
COPY mpack/fuzz_mpack.c /work/build-cov/
COPY mpack/fuzz_mpack.c /work/build-uftrace/

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN afl-clang-lto -O2 -DMPACK_READER=1 -DMPACK_EXTENSIONS=1 \
    -static -Wl,--allow-multiple-definition \
    -o fuzz_mpack fuzz_mpack.c src/mpack/mpack.c -lm

WORKDIR /work
RUN ln -s build-fuzz/fuzz_mpack bin-fuzz && \
    /work/bin-fuzz || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -DMPACK_READER=1 -DMPACK_EXTENSIONS=1 \
    -static -Wl,--allow-multiple-definition \
    -o fuzz_mpack fuzz_mpack.c src/mpack/mpack.c -lm

WORKDIR /work
RUN ln -s build-cmplog/fuzz_mpack bin-cmplog && \
    /work/bin-cmplog || true

# Copy fuzzing resources
COPY mpack/fuzz/dict /work/dict
COPY mpack/fuzz/in /work/in
COPY mpack/fuzz/fuzz.sh /work/fuzz.sh
COPY mpack/fuzz/whatsup.sh /work/whatsup.sh
COPY mpack/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY mpack/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY mpack/fuzz/collect-branch.py /work/collect-branch.py
COPY mpack/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY mpack/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -DMPACK_READER=1 -DMPACK_EXTENSIONS=1 \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    -o fuzz_mpack fuzz_mpack.c src/mpack/mpack.c -lm

WORKDIR /work
RUN ln -s build-cov/fuzz_mpack bin-cov && \
    /work/bin-cov || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN clang -g -O0 -pg -fno-omit-frame-pointer -DMPACK_READER=1 -DMPACK_EXTENSIONS=1 \
    -pg -Wl,--allow-multiple-definition \
    -o fuzz_mpack fuzz_mpack.c src/mpack/mpack.c -lm

WORKDIR /work
RUN ln -s build-uftrace/fuzz_mpack bin-uftrace && \
    /work/bin-uftrace || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
