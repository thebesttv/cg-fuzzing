FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libaio-dev libapparmor-dev libattr1-dev libbsd-dev libcap-dev libgcrypt-dev libipsec-mb-dev libjudy-dev libkeyutils-dev libkmod-dev libsctp-dev libxxhash-dev zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: stress-ng" > /work/proj && \
    echo "version: 0.18.05" >> /work/proj && \
    echo "source: https://github.com/ColinIanKing/stress-ng/archive/V0.18.05.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ColinIanKing/stress-ng/archive/V0.18.05.tar.gz && \
    tar -xzf V0.18.05.tar.gz && \
    rm V0.18.05.tar.gz && \
    cp -a stress-ng-0.18.05 build-fuzz && \
    cp -a stress-ng-0.18.05 build-cmplog && \
    cp -a stress-ng-0.18.05 build-cov && \
    cp -a stress-ng-0.18.05 build-uftrace && \
    rm -rf stress-ng-0.18.05

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc) STATIC=1

WORKDIR /work
RUN ln -s build-fuzz/stress-ng bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc) STATIC=1

WORKDIR /work
RUN ln -s build-cmplog/stress-ng bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY stress-ng/fuzz/dict /work/dict
COPY stress-ng/fuzz/in /work/in
COPY stress-ng/fuzz/fuzz.sh /work/fuzz.sh
COPY stress-ng/fuzz/whatsup.sh /work/whatsup.sh
COPY stress-ng/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY stress-ng/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY stress-ng/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    make -j$(nproc) STATIC=1

WORKDIR /work
RUN ln -s build-cov/stress-ng bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make -j$(nproc) STATIC=1

WORKDIR /work
RUN ln -s build-uftrace/stress-ng bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
