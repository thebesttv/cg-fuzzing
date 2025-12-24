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
RUN echo "project: parson" > /work/proj && \
    echo "version: ba29f4eda9ea7703a9f6a9cf2b0532a2605723c3" >> /work/proj && \
    echo "source: https://github.com/kgabis/parson/archive/ba29f4eda9ea7703a9f6a9cf2b0532a2605723c3.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/kgabis/parson/archive/ba29f4eda9ea7703a9f6a9cf2b0532a2605723c3.tar.gz -O parson.tar.gz && \
    tar -xzf parson.tar.gz && \
    rm parson.tar.gz && \
    mv parson-ba29f4eda9ea7703a9f6a9cf2b0532a2605723c3 parson-src && \
    cp -a parson-src build-fuzz && \
    cp -a parson-src build-cmplog && \
    cp -a parson-src build-cov && \
    cp -a parson-src build-uftrace && \
    rm -rf parson-src

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
COPY parson/fuzz/harness.c harness.c
RUN afl-clang-lto -O2 -c parson.c -o parson.o && \
    afl-clang-lto -O2 -I. harness.c parson.o -o parson_harness \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-fuzz/parson_harness bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
COPY parson/fuzz/harness.c harness.c
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -c parson.c -o parson.o && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I. harness.c parson.o -o parson_harness \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cmplog/parson_harness bin-cmplog

# Copy fuzzing resources
COPY parson/fuzz/dict /work/dict
COPY parson/fuzz/in /work/in
COPY parson/fuzz/fuzz.sh /work/fuzz.sh
COPY parson/fuzz/whatsup.sh /work/whatsup.sh
COPY parson/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY parson/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY parson/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
COPY parson/fuzz/harness.c harness.c
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -c parson.c -o parson.o && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I. harness.c parson.o -o parson_harness \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cov/parson_harness bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
COPY parson/fuzz/harness.c harness.c
RUN clang -g -O0 -pg -fno-omit-frame-pointer -c parson.c -o parson.o && \
    clang -g -O0 -pg -fno-omit-frame-pointer -I. harness.c parson.o -o parson_harness \
    -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-uftrace/parson_harness bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
