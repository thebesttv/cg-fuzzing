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
RUN echo "project: moreutils" > /work/proj && \
    echo "version: 0.69" >> /work/proj && \
    echo "source: https://git.joeyh.name/index.cgi/moreutils.git/snapshot/moreutils-0.69.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://git.joeyh.name/index.cgi/moreutils.git/snapshot/moreutils-0.69.tar.gz && \
    tar -xzf moreutils-0.69.tar.gz && \
    rm moreutils-0.69.tar.gz && \
    cp -a moreutils-0.69 build-fuzz && \
    cp -a moreutils-0.69 build-cmplog && \
    cp -a moreutils-0.69 build-cov && \
    cp -a moreutils-0.69 build-uftrace && \
    rm -rf moreutils-0.69

# Build fuzz binary with afl-clang-lto (focus on pee and ifne)
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make pee ifne -j$(nproc) || true

WORKDIR /work
RUN ln -s build-fuzz/pee bin-fuzz-pee && \
    ln -s build-fuzz/ifne bin-fuzz-ifne && \
    test -x /work/bin-fuzz-pee && echo "bin-fuzz-pee created successfully"

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make pee ifne -j$(nproc) || true

WORKDIR /work
RUN ln -s build-cmplog/pee bin-cmplog-pee && \
    ln -s build-cmplog/ifne bin-cmplog-ifne && \
    test -x /work/bin-cmplog-pee && echo "bin-cmplog-pee created successfully"

# Copy fuzzing resources
COPY moreutils/fuzz/dict /work/dict
COPY moreutils/fuzz/in /work/in
COPY moreutils/fuzz/fuzz.sh /work/fuzz.sh
COPY moreutils/fuzz/whatsup.sh /work/whatsup.sh
COPY moreutils/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY moreutils/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY moreutils/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    make pee ifne -j$(nproc) || true

WORKDIR /work
RUN ln -s build-cov/pee bin-cov-pee && \
    ln -s build-cov/ifne bin-cov-ifne && \
    test -x /work/bin-cov-pee && echo "bin-cov-pee created successfully" && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make pee ifne -j$(nproc) || true

WORKDIR /work
RUN ln -s build-uftrace/pee bin-uftrace-pee && \
    ln -s build-uftrace/ifne bin-uftrace-ifne && \
    test -x /work/bin-uftrace-pee && echo "bin-uftrace-pee created successfully" && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
