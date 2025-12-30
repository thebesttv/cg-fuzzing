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
RUN echo "project: libcsv" > /work/proj && \
    echo "version: 3.0.3" >> /work/proj && \
    echo "source: https://sourceforge.net/projects/libcsv/files/libcsv/libcsv-3.0.3/libcsv-3.0.3.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget -O libcsv-3.0.3.tar.gz "https://sourceforge.net/projects/libcsv/files/libcsv/libcsv-3.0.3/libcsv-3.0.3.tar.gz/download" && \
    tar -xzf libcsv-3.0.3.tar.gz && \
    rm libcsv-3.0.3.tar.gz && \
    cp -a libcsv-3.0.3 build-fuzz && \
    cp -a libcsv-3.0.3 build-cmplog && \
    cp -a libcsv-3.0.3 build-cov && \
    cp -a libcsv-3.0.3 build-uftrace && \
    rm -rf libcsv-3.0.3

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

# Build example tools with afl-clang-lto
RUN mkdir -p libcsv && cp csv.h libcsv/csv.h && \
    cd examples && \
    afl-clang-lto -O2 -I.. -static -Wl,--allow-multiple-definition -o csvinfo csvinfo.c ../.libs/libcsv.a

WORKDIR /work
RUN ln -s build-fuzz/examples/csvinfo bin-fuzz && \
    /work/bin-fuzz /work/proj

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build CMPLOG example tools
RUN mkdir -p libcsv && cp csv.h libcsv/csv.h && \
    cd examples && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I.. -static -Wl,--allow-multiple-definition -o csvinfo csvinfo.c ../.libs/libcsv.a

WORKDIR /work
RUN ln -s build-cmplog/examples/csvinfo bin-cmplog && \
    /work/bin-cmplog /work/proj

# Copy fuzzing resources
COPY libcsv/fuzz/dict /work/dict
COPY libcsv/fuzz/in /work/in
COPY libcsv/fuzz/fuzz.sh /work/fuzz.sh
COPY libcsv/fuzz/whatsup.sh /work/whatsup.sh
COPY libcsv/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libcsv/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libcsv/fuzz/collect-branch.py /work/collect-branch.py
COPY libcsv/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY libcsv/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

# Build cov example tools
RUN mkdir -p libcsv && cp csv.h libcsv/csv.h && \
    cd examples && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I.. -static -Wl,--allow-multiple-definition -fprofile-instr-generate -fcoverage-mapping -o csvinfo csvinfo.c ../.libs/libcsv.a

WORKDIR /work
RUN ln -s build-cov/examples/csvinfo bin-cov && \
    /work/bin-cov /work/proj && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

# Build uftrace example tools
RUN mkdir -p libcsv && cp csv.h libcsv/csv.h && \
    cd examples && \
    clang -g -O0 -pg -fno-omit-frame-pointer -I.. -Wl,--allow-multiple-definition -pg -o csvinfo csvinfo.c ../.libs/libcsv.a

WORKDIR /work
RUN ln -s build-uftrace/examples/csvinfo bin-uftrace && \
    /work/bin-uftrace /work/proj && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
