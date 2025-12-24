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
RUN echo "project: c-ares" > /work/proj && \
    echo "version: 1.34.5" >> /work/proj && \
    echo "source: https://github.com/c-ares/c-ares/releases/download/v1.34.5/c-ares-1.34.5.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/c-ares/c-ares/releases/download/v1.34.5/c-ares-1.34.5.tar.gz && \
    tar -xzf c-ares-1.34.5.tar.gz && \
    rm c-ares-1.34.5.tar.gz && \
    cp -a c-ares-1.34.5 build-fuzz && \
    cp -a c-ares-1.34.5 build-cmplog && \
    cp -a c-ares-1.34.5 build-cov && \
    cp -a c-ares-1.34.5 build-uftrace && \
    rm -rf c-ares-1.34.5

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DCARES_STATIC=ON \
        -DCARES_SHARED=OFF \
        -DCARES_BUILD_TOOLS=ON \
        -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/bin/adig bin-fuzz && \
    /work/bin-fuzz --help 2>&1 | head -5 || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DCARES_STATIC=ON \
        -DCARES_SHARED=OFF \
        -DCARES_BUILD_TOOLS=ON \
        -DCMAKE_BUILD_TYPE=Release && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/bin/adig bin-cmplog && \
    /work/bin-cmplog --help 2>&1 | head -5 || true

# Copy fuzzing resources
COPY c-ares/fuzz/dict /work/dict
COPY c-ares/fuzz/in /work/in
COPY c-ares/fuzz/fuzz.sh /work/fuzz.sh
COPY c-ares/fuzz/whatsup.sh /work/whatsup.sh
COPY c-ares/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY c-ares/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY c-ares/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DCARES_STATIC=ON \
        -DCARES_SHARED=OFF \
        -DCARES_BUILD_TOOLS=ON \
        -DCMAKE_BUILD_TYPE=Debug && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/bin/adig bin-cov && \
    /work/bin-cov --help 2>&1 | head -5 || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DCARES_STATIC=ON \
        -DCARES_SHARED=OFF \
        -DCARES_BUILD_TOOLS=ON \
        -DCMAKE_BUILD_TYPE=Debug && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/build/bin/adig bin-uftrace && \
    /work/bin-uftrace --help 2>&1 | head -5 || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
