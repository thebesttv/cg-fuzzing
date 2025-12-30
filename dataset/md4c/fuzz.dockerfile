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
RUN echo "project: md4c" > /work/proj && \
    echo "version: release-0.5.2" >> /work/proj && \
    echo "source: https://github.com/mity/md4c/archive/refs/tags/release-0.5.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/mity/md4c/archive/refs/tags/release-0.5.2.tar.gz && \
    tar -xzf release-0.5.2.tar.gz && \
    rm release-0.5.2.tar.gz && \
    cp -a md4c-release-0.5.2 build-fuzz && \
    cp -a md4c-release-0.5.2 build-cmplog && \
    cp -a md4c-release-0.5.2 build-cov && \
    cp -a md4c-release-0.5.2 build-uftrace && \
    rm -rf md4c-release-0.5.2

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
RUN ln -s build-fuzz/build/md2html/md2html bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/md2html/md2html bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY md4c/fuzz/dict /work/dict
COPY md4c/fuzz/in /work/in
COPY md4c/fuzz/fuzz.sh /work/fuzz.sh
COPY md4c/fuzz/whatsup.sh /work/whatsup.sh
COPY md4c/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY md4c/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY md4c/fuzz/collect-branch.py /work/collect-branch.py
COPY md4c/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY md4c/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

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
RUN ln -s build-cov/build/md2html/md2html bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
    -DCMAKE_INSTALL_PREFIX=/work/install-uftrace \
    -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/md2html bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
