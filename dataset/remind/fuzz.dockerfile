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
RUN echo "project: remind" > /work/proj && \
    echo "version: 06.02.01" >> /work/proj && \
    echo "source: https://dianne.skoll.ca/projects/remind/download/remind-06.02.01.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://dianne.skoll.ca/projects/remind/download/remind-06.02.01.tar.gz && \
    tar -xzf remind-06.02.01.tar.gz && \
    rm remind-06.02.01.tar.gz && \
    cp -a remind-06.02.01 build-fuzz && \
    cp -a remind-06.02.01 build-cmplog && \
    cp -a remind-06.02.01 build-cov && \
    cp -a remind-06.02.01 build-uftrace && \
    rm -rf remind-06.02.01

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/remind bin-fuzz && \
    /work/bin-fuzz -v || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/remind bin-cmplog && \
    /work/bin-cmplog -v || true

# Copy fuzzing resources
COPY remind/fuzz/dict /work/dict
COPY remind/fuzz/in /work/in
COPY remind/fuzz/fuzz.sh /work/fuzz.sh
COPY remind/fuzz/whatsup.sh /work/whatsup.sh
COPY remind/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY remind/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY remind/fuzz/collect-branch.py /work/collect-branch.py
COPY remind/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/remind bin-cov && \
    /work/bin-cov -v || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/remind bin-uftrace && \
    /work/bin-uftrace -v || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
