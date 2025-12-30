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
RUN echo "project: bibutils" > /work/proj && \
    echo "version: 7.2" >> /work/proj && \
    echo "source: https://sourceforge.net/projects/bibutils/files/bibutils_7.2_src.tgz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 "https://sourceforge.net/projects/bibutils/files/bibutils_7.2_src.tgz/download" -O bibutils_7.2_src.tgz && \
    tar -xzf bibutils_7.2_src.tgz && \
    rm bibutils_7.2_src.tgz && \
    cp -a bibutils_7.2 build-fuzz && \
    cp -a bibutils_7.2 build-cmplog && \
    cp -a bibutils_7.2 build-cov && \
    cp -a bibutils_7.2 build-uftrace && \
    rm -rf bibutils_7.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./configure --static && \
    sed -i 's|^CC.*=.*|CC = afl-clang-lto|' Makefile && \
    sed -i 's|^CFLAGS.*=.*|CFLAGS = -O2|' Makefile && \
    LDFLAGS="-static -Wl,--allow-multiple-definition" make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/bin/bib2xml bin-fuzz && \
    /work/bin-fuzz -h 2>&1 | head -3

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN ./configure --static && \
    sed -i 's|^CC.*=.*|CC = afl-clang-lto|' Makefile && \
    sed -i 's|^CFLAGS.*=.*|CFLAGS = -O2|' Makefile && \
    AFL_LLVM_CMPLOG=1 LDFLAGS="-static -Wl,--allow-multiple-definition" make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/bin/bib2xml bin-cmplog && \
    /work/bin-cmplog -h 2>&1 | head -3

# Copy fuzzing resources
COPY bibutils/fuzz/dict /work/dict
COPY bibutils/fuzz/in /work/in
COPY bibutils/fuzz/fuzz.sh /work/fuzz.sh
COPY bibutils/fuzz/whatsup.sh /work/whatsup.sh
COPY bibutils/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY bibutils/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY bibutils/fuzz/collect-branch.py /work/collect-branch.py
COPY bibutils/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./configure --static && \
    sed -i 's|^CC.*=.*|CC = clang|' Makefile && \
    sed -i 's|^CFLAGS.*=.*|CFLAGS = -g -O0 -fprofile-instr-generate -fcoverage-mapping|' Makefile && \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/bin/bib2xml bin-cov && \
    /work/bin-cov -h 2>&1 | head -3 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./configure --static && \
    sed -i 's|^CC.*=.*|CC = clang|' Makefile && \
    sed -i 's|^CFLAGS.*=.*|CFLAGS = -g -O0 -pg -fno-omit-frame-pointer|' Makefile && \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/bin/bib2xml bin-uftrace && \
    /work/bin-uftrace -h 2>&1 | head -3 && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
