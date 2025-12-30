FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: miniz" > /work/proj && \
    echo "version: 3.1.0" >> /work/proj && \
    echo "source: https://github.com/richgel999/miniz/archive/refs/tags/3.1.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/richgel999/miniz/archive/refs/tags/3.1.0.tar.gz && \
    tar -xzf 3.1.0.tar.gz && \
    rm 3.1.0.tar.gz && \
    cp -a miniz-3.1.0 build-fuzz && \
    cp -a miniz-3.1.0 build-cmplog && \
    cp -a miniz-3.1.0 build-cov && \
    cp -a miniz-3.1.0 build-uftrace && \
    rm -rf miniz-3.1.0

# Copy harness source
COPY miniz/fuzz_harness.c /work/harness.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make miniz

RUN afl-clang-lto \
    -O2 \
    -I. -Ibuild \
    -static -Wl,--allow-multiple-definition \
    -o miniz_fuzz \
    /work/harness.c build/libminiz.a

WORKDIR /work
RUN ln -s build-fuzz/miniz_fuzz bin-fuzz && \
    echo "test" | /work/bin-fuzz /dev/stdin || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    AFL_LLVM_CMPLOG=1 make miniz

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto \
    -O2 \
    -I. -Ibuild \
    -static -Wl,--allow-multiple-definition \
    -o miniz_fuzz \
    /work/harness.c build/libminiz.a

WORKDIR /work
RUN ln -s build-cmplog/miniz_fuzz bin-cmplog && \
    echo "test" | /work/bin-cmplog /dev/stdin || true

# Copy fuzzing resources
COPY miniz/fuzz/dict /work/dict
COPY miniz/fuzz/in /work/in
COPY miniz/fuzz/fuzz.sh /work/fuzz.sh
COPY miniz/fuzz/whatsup.sh /work/whatsup.sh
COPY miniz/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY miniz/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY miniz/fuzz/collect-branch.py /work/collect-branch.py
COPY miniz/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make miniz

RUN clang \
    -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I. -Ibuild \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    -o miniz_fuzz \
    /work/harness.c build/libminiz.a

WORKDIR /work
RUN ln -s build-cov/miniz_fuzz bin-cov && \
    echo "test" | /work/bin-cov /dev/stdin || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make miniz

RUN clang \
    -g -O0 -pg -fno-omit-frame-pointer \
    -I. -Ibuild \
    -pg -Wl,--allow-multiple-definition \
    -o miniz_fuzz \
    /work/harness.c build/libminiz.a

WORKDIR /work
RUN ln -s build-uftrace/miniz_fuzz bin-uftrace && \
    echo "test" | /work/bin-uftrace /dev/stdin || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
