FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: lzop" > /work/proj && \
    echo "version: 1.04" >> /work/proj && \
    echo "source: https://www.lzop.org/download/lzop-1.04.tar.gz" >> /work/proj

# Download lzo library source (dependency)
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz && \
    tar -xzf lzo-2.10.tar.gz && \
    rm lzo-2.10.tar.gz

# Download lzop source
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.lzop.org/download/lzop-1.04.tar.gz && \
    tar -xzf lzop-1.04.tar.gz && \
    rm lzop-1.04.tar.gz

# Create build directories
RUN cp -a lzo-2.10 lzo-build-fuzz && \
    cp -a lzo-2.10 lzo-build-cmplog && \
    cp -a lzo-2.10 lzo-build-cov && \
    cp -a lzo-2.10 lzo-build-uftrace && \
    rm -rf lzo-2.10 && \
    cp -a lzop-1.04 build-fuzz && \
    cp -a lzop-1.04 build-cmplog && \
    cp -a lzop-1.04 build-cov && \
    cp -a lzop-1.04 build-uftrace && \
    rm -rf lzop-1.04

# Build fuzz: lzo library first
WORKDIR /work/lzo-build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    ./configure --disable-shared --enable-static --prefix=/work/install-fuzz && \
    make -j$(nproc) && \
    make install

# Build fuzz: lzop binary
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2 -I/work/install-fuzz/include" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -L/work/install-fuzz/lib" \
    ./configure --disable-asm && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/lzop bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog: lzo library first
WORKDIR /work/lzo-build-cmplog
RUN CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    CFLAGS="-O2" \
    ./configure --disable-shared --enable-static --prefix=/work/install-cmplog && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    make install

# Build cmplog: lzop binary
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    CFLAGS="-O2 -I/work/install-cmplog/include" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -L/work/install-cmplog/lib" \
    ./configure --disable-asm && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/lzop bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY lzop/fuzz/dict /work/dict
COPY lzop/fuzz/in /work/in
COPY lzop/fuzz/fuzz.sh /work/fuzz.sh
COPY lzop/fuzz/whatsup.sh /work/whatsup.sh
COPY lzop/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY lzop/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY lzop/fuzz/collect-branch.py /work/collect-branch.py
COPY lzop/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov: lzo library first
WORKDIR /work/lzo-build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping" \
    ./configure --disable-shared --enable-static --prefix=/work/install-cov && \
    make -j$(nproc) && \
    make install

# Build cov: lzop binary
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -I/work/install-cov/include" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition -L/work/install-cov/lib" \
    ./configure --disable-asm && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/lzop bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace: lzo library first
WORKDIR /work/lzo-build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg" \
    ./configure --disable-shared --enable-static --prefix=/work/install-uftrace-lzo && \
    make -j$(nproc) && \
    make install

# Build uftrace: lzop binary
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer -I/work/install-uftrace-lzo/include" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition -L/work/install-uftrace-lzo/lib" \
    ./configure --disable-asm --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/lzop bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
