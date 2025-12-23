FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libpng-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: jbig2dec" > /work/proj && \
    echo "version: 0.20" >> /work/proj && \
    echo "source: https://github.com/ArtifexSoftware/jbig2dec/archive/refs/tags/0.20.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ArtifexSoftware/jbig2dec/archive/refs/tags/0.20.tar.gz -O jbig2dec-0.20.tar.gz && \
    tar -xzf jbig2dec-0.20.tar.gz && \
    rm jbig2dec-0.20.tar.gz && \
    cp -a jbig2dec-0.20 build-fuzz && \
    cp -a jbig2dec-0.20 build-cmplog && \
    cp -a jbig2dec-0.20 build-cov && \
    cp -a jbig2dec-0.20 build-uftrace && \
    rm -rf jbig2dec-0.20

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make -f Makefile.unix \
    CC=afl-clang-lto \
    CFLAGS="-O2 -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    jbig2dec

WORKDIR /work
RUN ln -s build-fuzz/jbig2dec bin-fuzz && \
    /work/bin-fuzz --version || /work/bin-fuzz --help || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make -f Makefile.unix \
    CC=afl-clang-lto \
    CFLAGS="-O2 -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    jbig2dec

WORKDIR /work
RUN ln -s build-cmplog/jbig2dec bin-cmplog && \
    /work/bin-cmplog --version || /work/bin-cmplog --help || true

# Copy fuzzing resources
COPY jbig2dec/fuzz/dict /work/dict
COPY jbig2dec/fuzz/in /work/in
COPY jbig2dec/fuzz/fuzz.sh /work/fuzz.sh
COPY jbig2dec/fuzz/whatsup.sh /work/whatsup.sh
COPY jbig2dec/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make -f Makefile.unix \
    CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    jbig2dec

WORKDIR /work
RUN ln -s build-cov/jbig2dec bin-cov && \
    /work/bin-cov --version || /work/bin-cov --help || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make -f Makefile.unix \
    CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    jbig2dec

WORKDIR /work
RUN ln -s build-uftrace/jbig2dec bin-uftrace && \
    /work/bin-uftrace --version || /work/bin-uftrace --help || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
