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
RUN echo "project: par" > /work/proj && \
    echo "version: 1.53.0" >> /work/proj && \
    echo "source: http://www.nicemice.net/par/Par-1.53.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 http://www.nicemice.net/par/Par-1.53.0.tar.gz && \
    tar -xzf Par-1.53.0.tar.gz && \
    rm Par-1.53.0.tar.gz && \
    cp -a Par-1.53.0 build-fuzz && \
    cp -a Par-1.53.0 build-cmplog && \
    cp -a Par-1.53.0 build-cov && \
    cp -a Par-1.53.0 build-uftrace && \
    rm -rf Par-1.53.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN afl-clang-lto -c -O2 buffer.c && \
    afl-clang-lto -c -O2 charset.c && \
    afl-clang-lto -c -O2 errmsg.c && \
    afl-clang-lto -c -O2 reformat.c && \
    afl-clang-lto -c -O2 par.c && \
    afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
        buffer.o charset.o errmsg.o reformat.o par.o -o par

WORKDIR /work
RUN ln -s build-fuzz/par bin-fuzz && \
    echo "Test:" | /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 buffer.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 charset.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 errmsg.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 reformat.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 par.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
        buffer.o charset.o errmsg.o reformat.o par.o -o par

WORKDIR /work
RUN ln -s build-cmplog/par bin-cmplog && \
    echo "Test:" | /work/bin-cmplog

# Copy fuzzing resources
COPY par/fuzz/dict /work/dict
COPY par/fuzz/in /work/in
COPY par/fuzz/fuzz.sh /work/fuzz.sh
COPY par/fuzz/whatsup.sh /work/whatsup.sh
COPY par/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY par/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY par/fuzz/collect-branch.py /work/collect-branch.py
COPY par/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN clang -c -g -O0 -fprofile-instr-generate -fcoverage-mapping buffer.c && \
    clang -c -g -O0 -fprofile-instr-generate -fcoverage-mapping charset.c && \
    clang -c -g -O0 -fprofile-instr-generate -fcoverage-mapping errmsg.c && \
    clang -c -g -O0 -fprofile-instr-generate -fcoverage-mapping reformat.c && \
    clang -c -g -O0 -fprofile-instr-generate -fcoverage-mapping par.c && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
        buffer.o charset.o errmsg.o reformat.o par.o -o par

WORKDIR /work
RUN ln -s build-cov/par bin-cov && \
    echo "Test:" | /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN clang -c -g -O0 -pg -fno-omit-frame-pointer buffer.c && \
    clang -c -g -O0 -pg -fno-omit-frame-pointer charset.c && \
    clang -c -g -O0 -pg -fno-omit-frame-pointer errmsg.c && \
    clang -c -g -O0 -pg -fno-omit-frame-pointer reformat.c && \
    clang -c -g -O0 -pg -fno-omit-frame-pointer par.c && \
    clang -g -O0 -pg -fno-omit-frame-pointer -Wl,--allow-multiple-definition \
        buffer.o charset.o errmsg.o reformat.o par.o -o par

WORKDIR /work
RUN ln -s build-uftrace/par bin-uftrace && \
    echo "Test:" | /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
