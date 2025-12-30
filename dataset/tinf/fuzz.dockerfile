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
RUN echo "project: tinf" > /work/proj && \
    echo "version: 1.2.1" >> /work/proj && \
    echo "source: https://github.com/jibsen/tinf/archive/refs/tags/v1.2.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jibsen/tinf/archive/refs/tags/v1.2.1.tar.gz && \
    tar -xzf v1.2.1.tar.gz && \
    rm v1.2.1.tar.gz && \
    cp -a tinf-1.2.1 build-fuzz && \
    cp -a tinf-1.2.1 build-cmplog && \
    cp -a tinf-1.2.1 build-cov && \
    cp -a tinf-1.2.1 build-uftrace && \
    rm -rf tinf-1.2.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/tgunzip bin-fuzz && \
    /work/bin-fuzz --version || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/tgunzip bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY tinf/fuzz/dict /work/dict
COPY tinf/fuzz/in /work/in
COPY tinf/fuzz/fuzz.sh /work/fuzz.sh
COPY tinf/fuzz/whatsup.sh /work/whatsup.sh
COPY tinf/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY tinf/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY tinf/fuzz/collect-branch.py /work/collect-branch.py
COPY tinf/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/tgunzip bin-cov && \
    /work/bin-cov --version || true && \
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
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/build/tgunzip bin-uftrace && \
    /work/bin-uftrace --version || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
