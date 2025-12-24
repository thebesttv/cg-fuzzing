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
RUN echo "project: base64" > /work/proj && \
    echo "version: 0.5.2" >> /work/proj && \
    echo "source: https://github.com/aklomp/base64/archive/refs/tags/v0.5.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/aklomp/base64/archive/refs/tags/v0.5.2.tar.gz && \
    tar -xzf v0.5.2.tar.gz && \
    rm v0.5.2.tar.gz && \
    cp -a base64-0.5.2 build-fuzz && \
    cp -a base64-0.5.2 build-cmplog && \
    cp -a base64-0.5.2 build-cov && \
    cp -a base64-0.5.2 build-uftrace && \
    rm -rf base64-0.5.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBASE64_BUILD_CLI=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/bin/base64 bin-fuzz && \
    echo "base64 binary created"

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBASE64_BUILD_CLI=ON && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/bin/base64 bin-cmplog && \
    echo "base64 cmplog binary created"

# Copy fuzzing resources
COPY base64/fuzz/dict /work/dict
COPY base64/fuzz/in /work/in
COPY base64/fuzz/fuzz.sh /work/fuzz.sh
COPY base64/fuzz/whatsup.sh /work/whatsup.sh
COPY base64/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY base64/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY base64/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBASE64_BUILD_CLI=ON && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/bin/base64 bin-cov && \
    echo "base64 cov binary created" && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBASE64_BUILD_CLI=ON \
    -DCMAKE_INSTALL_PREFIX=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/base64 bin-uftrace && \
    echo "base64 uftrace binary created" && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
