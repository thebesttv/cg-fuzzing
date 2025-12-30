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
RUN echo "project: enchive" > /work/proj && \
    echo "version: 3.5" >> /work/proj && \
    echo "source: https://github.com/skeeto/enchive/archive/refs/tags/3.5.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/skeeto/enchive/archive/refs/tags/3.5.tar.gz && \
    tar -xzf 3.5.tar.gz && \
    rm 3.5.tar.gz && \
    cp -a enchive-3.5 build-fuzz && \
    cp -a enchive-3.5 build-cmplog && \
    cp -a enchive-3.5 build-cov && \
    cp -a enchive-3.5 build-uftrace && \
    rm -rf enchive-3.5

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-fuzz/enchive bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-cmplog/enchive bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY enchive/fuzz/dict /work/dict
COPY enchive/fuzz/in /work/in
COPY enchive/fuzz/fuzz.sh /work/fuzz.sh
COPY enchive/fuzz/whatsup.sh /work/whatsup.sh
COPY enchive/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY enchive/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY enchive/fuzz/collect-branch.py /work/collect-branch.py
COPY enchive/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-cov/enchive bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-uftrace/enchive bin-uftrace && \
    /work/bin-uftrace --version && \
    uftrace record /work/bin-uftrace --version && \
    uftrace report && \
    rm -rf uftrace.data gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
