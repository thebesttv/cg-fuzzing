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
RUN echo "project: uriparser" > /work/proj && \
    echo "version: 0.9.9" >> /work/proj && \
    echo "source: https://github.com/uriparser/uriparser/releases/download/uriparser-0.9.9/uriparser-0.9.9.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/uriparser/uriparser/releases/download/uriparser-0.9.9/uriparser-0.9.9.tar.gz && \
    tar -xzf uriparser-0.9.9.tar.gz && \
    rm uriparser-0.9.9.tar.gz && \
    cp -a uriparser-0.9.9 build-fuzz && \
    cp -a uriparser-0.9.9 build-cmplog && \
    cp -a uriparser-0.9.9 build-cov && \
    cp -a uriparser-0.9.9 build-uftrace && \
    rm -rf uriparser-0.9.9

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DURIPARSER_BUILD_TESTS=OFF \
        -DURIPARSER_BUILD_DOCS=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/uriparse bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DURIPARSER_BUILD_TESTS=OFF \
        -DURIPARSER_BUILD_DOCS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/uriparse bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY uriparser/fuzz/dict /work/dict
COPY uriparser/fuzz/in /work/in
COPY uriparser/fuzz/fuzz.sh /work/fuzz.sh
COPY uriparser/fuzz/whatsup.sh /work/whatsup.sh
COPY uriparser/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY uriparser/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY uriparser/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_CXX_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DURIPARSER_BUILD_TESTS=OFF \
        -DURIPARSER_BUILD_DOCS=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/uriparse bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_CXX_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DURIPARSER_BUILD_TESTS=OFF \
        -DURIPARSER_BUILD_DOCS=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/build/uriparse bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
