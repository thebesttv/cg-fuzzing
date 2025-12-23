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
RUN echo "project: iniparser" > /work/proj && \
    echo "version: 4.2.6" >> /work/proj && \
    echo "source: https://github.com/ndevilla/iniparser/archive/refs/tags/v4.2.6.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ndevilla/iniparser/archive/refs/tags/v4.2.6.tar.gz && \
    tar -xzf v4.2.6.tar.gz && \
    rm v4.2.6.tar.gz && \
    cp -a iniparser-4.2.6 build-fuzz && \
    cp -a iniparser-4.2.6 build-cmplog && \
    cp -a iniparser-4.2.6 build-cov && \
    cp -a iniparser-4.2.6 build-uftrace && \
    rm -rf iniparser-4.2.6

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc)

RUN afl-clang-lto -O2 -I src \
    -static -Wl,--allow-multiple-definition \
    example/parse.c build/libiniparser.a -o parse

WORKDIR /work
RUN ln -s build-fuzz/parse bin-fuzz && \
    /work/bin-fuzz /work/build-fuzz/example/twisted.ini

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

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I src \
    -static -Wl,--allow-multiple-definition \
    example/parse.c build/libiniparser.a -o parse

WORKDIR /work
RUN ln -s build-cmplog/parse bin-cmplog && \
    /work/bin-cmplog /work/build-cmplog/example/twisted.ini

# Copy fuzzing resources
COPY iniparser/fuzz/dict /work/dict
COPY iniparser/fuzz/in /work/in
COPY iniparser/fuzz/fuzz.sh /work/fuzz.sh
COPY iniparser/fuzz/whatsup.sh /work/whatsup.sh
COPY iniparser/fuzz/1-run-cov.sh /work/1-run-cov.sh

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

RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I src \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    example/parse.c build/libiniparser.a -o parse

WORKDIR /work
RUN ln -s build-cov/parse bin-cov && \
    /work/bin-cov /work/build-cov/example/twisted.ini && \
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

RUN clang -g -O0 -pg -fno-omit-frame-pointer -I src \
    -pg -Wl,--allow-multiple-definition \
    example/parse.c build/libiniparser.a -o parse

WORKDIR /work
RUN ln -s build-uftrace/parse bin-uftrace && \
    /work/bin-uftrace /work/build-uftrace/example/twisted.ini && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
