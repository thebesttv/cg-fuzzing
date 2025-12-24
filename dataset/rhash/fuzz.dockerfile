FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies (libssl-dev needed for configure even when openssl is disabled)
RUN apt-get update && \
    apt-get install -y wget libssl-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: rhash" > /work/proj && \
    echo "version: 1.4.5" >> /work/proj && \
    echo "source: https://github.com/rhash/RHash/archive/refs/tags/v1.4.5.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/rhash/RHash/archive/refs/tags/v1.4.5.tar.gz && \
    tar -xzf v1.4.5.tar.gz && \
    rm v1.4.5.tar.gz && \
    cp -a RHash-1.4.5 build-fuzz && \
    cp -a RHash-1.4.5 build-cmplog && \
    cp -a RHash-1.4.5 build-cov && \
    cp -a RHash-1.4.5 build-uftrace && \
    rm -rf RHash-1.4.5

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./configure --cc=afl-clang-lto --extra-cflags="-O2" --extra-ldflags="-static -Wl,--allow-multiple-definition" --disable-lib-shared --enable-static --disable-openssl --disable-openssl-runtime && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/rhash bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-lto --extra-cflags="-O2" --extra-ldflags="-static -Wl,--allow-multiple-definition" --disable-lib-shared --enable-static --disable-openssl --disable-openssl-runtime && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/rhash bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY rhash/fuzz/dict /work/dict
COPY rhash/fuzz/in /work/in
COPY rhash/fuzz/fuzz.sh /work/fuzz.sh
COPY rhash/fuzz/whatsup.sh /work/whatsup.sh
COPY rhash/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY rhash/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY rhash/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./configure --cc=clang --extra-cflags="-g -O0 -fprofile-instr-generate -fcoverage-mapping" --extra-ldflags="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" --disable-lib-shared --enable-static --disable-openssl --disable-openssl-runtime && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/rhash bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./configure --cc=clang --extra-cflags="-g -O0 -pg -fno-omit-frame-pointer" --extra-ldflags="-pg -Wl,--allow-multiple-definition" --disable-lib-shared --enable-static --disable-openssl --disable-openssl-runtime && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/rhash bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
