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
RUN echo "project: mpc" > /work/proj && \
    echo "version: 0.9.0" >> /work/proj && \
    echo "source: https://github.com/orangeduck/mpc/archive/refs/tags/0.9.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/orangeduck/mpc/archive/refs/tags/0.9.0.tar.gz && \
    tar -xzf 0.9.0.tar.gz && \
    rm 0.9.0.tar.gz && \
    cp -a mpc-0.9.0 build-fuzz && \
    cp -a mpc-0.9.0 build-cmplog && \
    cp -a mpc-0.9.0 build-cov && \
    cp -a mpc-0.9.0 build-uftrace && \
    rm -rf mpc-0.9.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN afl-clang-lto -O2 -ansi -pedantic -Wall \
    -static -Wl,--allow-multiple-definition \
    examples/maths.c mpc.c -lm -o maths

WORKDIR /work
RUN ln -s build-fuzz/maths bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -ansi -pedantic -Wall \
    -static -Wl,--allow-multiple-definition \
    examples/maths.c mpc.c -lm -o maths

WORKDIR /work
RUN ln -s build-cmplog/maths bin-cmplog

# Copy fuzzing resources
COPY mpc/fuzz/dict /work/dict
COPY mpc/fuzz/in /work/in
COPY mpc/fuzz/fuzz.sh /work/fuzz.sh
COPY mpc/fuzz/whatsup.sh /work/whatsup.sh
COPY mpc/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -static -Wl,--allow-multiple-definition \
    -ansi -pedantic -Wall \
    examples/maths.c mpc.c -lm -o maths

WORKDIR /work
RUN ln -s build-cov/maths bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN clang -g -O0 -pg -fno-omit-frame-pointer \
    -pg -Wl,--allow-multiple-definition \
    -ansi -pedantic -Wall \
    examples/maths.c mpc.c -lm -o maths

WORKDIR /work
RUN ln -s build-uftrace/maths bin-uftrace && \
    echo "1+1" | uftrace record /work/bin-uftrace && \
    uftrace report && \
    rm -rf uftrace.data gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
