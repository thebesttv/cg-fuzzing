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
RUN echo "project: lexbor" > /work/proj && \
    echo "version: 2.6.0" >> /work/proj && \
    echo "source: https://github.com/lexbor/lexbor/archive/refs/tags/v2.6.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/lexbor/lexbor/archive/refs/tags/v2.6.0.tar.gz && \
    tar -xzf v2.6.0.tar.gz && \
    rm v2.6.0.tar.gz && \
    cp -a lexbor-2.6.0 build-fuzz && \
    cp -a lexbor-2.6.0 build-cmplog && \
    cp -a lexbor-2.6.0 build-cov && \
    cp -a lexbor-2.6.0 build-uftrace && \
    rm -rf lexbor-2.6.0

# Copy harness file for all builds
COPY lexbor/fuzz/harness/afl_harness.c /work/afl_harness.c

# Build library with afl-clang-lto for fuzz
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DLEXBOR_BUILD_STATIC=ON \
        -DLEXBOR_BUILD_SHARED=OFF \
        -DLEXBOR_BUILD_EXAMPLES=OFF \
        -DLEXBOR_BUILD_TESTS=OFF && \
    make -j$(nproc)

# Compile fuzz harness
RUN afl-clang-lto -O2 -I/work/build-fuzz/source \
    /work/afl_harness.c \
    -o /work/build-fuzz/lexbor_html_fuzz \
    /work/build-fuzz/build/liblexbor_static.a -lm

WORKDIR /work
RUN ln -s build-fuzz/lexbor_html_fuzz bin-fuzz

# Build library with afl-clang-lto + CMPLOG for cmplog
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DLEXBOR_BUILD_STATIC=ON \
        -DLEXBOR_BUILD_SHARED=OFF \
        -DLEXBOR_BUILD_EXAMPLES=OFF \
        -DLEXBOR_BUILD_TESTS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Compile cmplog harness
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I/work/build-cmplog/source \
    /work/afl_harness.c \
    -o /work/build-cmplog/lexbor_html_fuzz \
    /work/build-cmplog/build/liblexbor_static.a -lm

WORKDIR /work
RUN ln -s build-cmplog/lexbor_html_fuzz bin-cmplog

# Copy fuzzing resources
COPY lexbor/fuzz/dict /work/dict
COPY lexbor/fuzz/in /work/in
COPY lexbor/fuzz/fuzz.sh /work/fuzz.sh
COPY lexbor/fuzz/whatsup.sh /work/whatsup.sh
COPY lexbor/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY lexbor/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY lexbor/fuzz/collect-branch.py /work/collect-branch.py

# Build library with llvm-cov instrumentation for cov
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DLEXBOR_BUILD_STATIC=ON \
        -DLEXBOR_BUILD_SHARED=OFF \
        -DLEXBOR_BUILD_EXAMPLES=OFF \
        -DLEXBOR_BUILD_TESTS=OFF && \
    make -j$(nproc)

# Compile cov harness
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I/work/build-cov/source \
    /work/afl_harness.c \
    -o /work/build-cov/lexbor_html_fuzz \
    /work/build-cov/build/liblexbor_static.a -lm

WORKDIR /work
RUN ln -s build-cov/lexbor_html_fuzz bin-cov && \
    rm -f *.profraw

# Build library with profiling instrumentation for uftrace
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_INSTALL_PREFIX=/work/install-uftrace \
        -DLEXBOR_BUILD_STATIC=ON \
        -DLEXBOR_BUILD_SHARED=OFF \
        -DLEXBOR_BUILD_EXAMPLES=OFF \
        -DLEXBOR_BUILD_TESTS=OFF && \
    make -j$(nproc) && \
    make install

# Compile uftrace harness
RUN clang -g -O0 -pg -fno-omit-frame-pointer \
    -I/work/build-uftrace/source \
    /work/afl_harness.c \
    -o /work/install-uftrace/lexbor_html_fuzz \
    /work/build-uftrace/build/liblexbor_static.a -lm

WORKDIR /work
RUN ln -s install-uftrace/lexbor_html_fuzz bin-uftrace

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
