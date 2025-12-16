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
RUN echo "project: tidy-html5" > /work/proj && \
    echo "version: 5.8.0" >> /work/proj && \
    echo "source: https://github.com/htacg/tidy-html5/archive/refs/tags/5.8.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/htacg/tidy-html5/archive/refs/tags/5.8.0.tar.gz && \
    tar -xzf 5.8.0.tar.gz && \
    rm 5.8.0.tar.gz && \
    cp -a tidy-html5-5.8.0 build-fuzz && \
    cp -a tidy-html5-5.8.0 build-cmplog && \
    cp -a tidy-html5-5.8.0 build-cov && \
    cp -a tidy-html5-5.8.0 build-uftrace && \
    rm -rf tidy-html5-5.8.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN rm -rf build && mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIB=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/tidy bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN rm -rf build && mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIB=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/tidy bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY tidy-html5/fuzz/dict /work/dict
COPY tidy-html5/fuzz/in /work/in
COPY tidy-html5/fuzz/fuzz.sh /work/fuzz.sh
COPY tidy-html5/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN rm -rf build && mkdir build && cd build && \
    CC=clang \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIB=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/tidy bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN rm -rf build && mkdir build && cd build && \
    CC=clang \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIB=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/build/tidy bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
