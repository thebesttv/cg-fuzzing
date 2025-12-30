FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake xz-utils uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: uchardet" > /work/proj && \
    echo "version: 0.0.8" >> /work/proj && \
    echo "source: https://www.freedesktop.org/software/uchardet/releases/uchardet-0.0.8.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.freedesktop.org/software/uchardet/releases/uchardet-0.0.8.tar.xz && \
    tar -xf uchardet-0.0.8.tar.xz && \
    rm uchardet-0.0.8.tar.xz && \
    cp -a uchardet-0.0.8 build-fuzz && \
    cp -a uchardet-0.0.8 build-cmplog && \
    cp -a uchardet-0.0.8 build-cov && \
    cp -a uchardet-0.0.8 build-uftrace && \
    rm -rf uchardet-0.0.8

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_BINARY=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/src/tools/uchardet bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    AFL_LLVM_CMPLOG=1 CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_BINARY=ON && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/src/tools/uchardet bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY uchardet/fuzz/dict /work/dict
COPY uchardet/fuzz/in /work/in
COPY uchardet/fuzz/fuzz.sh /work/fuzz.sh
COPY uchardet/fuzz/whatsup.sh /work/whatsup.sh
COPY uchardet/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY uchardet/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY uchardet/fuzz/collect-branch.py /work/collect-branch.py
COPY uchardet/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY uchardet/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_CXX_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_BINARY=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/src/tools/uchardet bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_CXX_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DCMAKE_INSTALL_PREFIX=/work/install-uftrace \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_BINARY=ON && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/uchardet bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
