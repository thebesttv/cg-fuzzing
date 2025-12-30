FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: odt2txt" > /work/proj && \
    echo "version: 0.5" >> /work/proj && \
    echo "source: https://github.com/dstosberg/odt2txt/archive/refs/tags/v0.5.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/dstosberg/odt2txt/archive/refs/tags/v0.5.tar.gz && \
    tar -xzf v0.5.tar.gz && \
    rm v0.5.tar.gz && \
    cp -a odt2txt-0.5 build-fuzz && \
    cp -a odt2txt-0.5 build-cmplog && \
    cp -a odt2txt-0.5 build-cov && \
    cp -a odt2txt-0.5 build-uftrace && \
    rm -rf odt2txt-0.5

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    make

WORKDIR /work
RUN ln -s build-fuzz/odt2txt bin-fuzz && \
    /work/bin-fuzz --version || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make

WORKDIR /work
RUN ln -s build-cmplog/odt2txt bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY odt2txt/fuzz/dict /work/dict
COPY odt2txt/fuzz/in /work/in
COPY odt2txt/fuzz/fuzz.sh /work/fuzz.sh
COPY odt2txt/fuzz/whatsup.sh /work/whatsup.sh
COPY odt2txt/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY odt2txt/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY odt2txt/fuzz/collect-branch.py /work/collect-branch.py
COPY odt2txt/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -Wl,--allow-multiple-definition" \
    make

WORKDIR /work
RUN ln -s build-cov/odt2txt bin-cov && \
    /work/bin-cov --version || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make

WORKDIR /work
RUN ln -s build-uftrace/odt2txt bin-uftrace && \
    /work/bin-uftrace --version || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
