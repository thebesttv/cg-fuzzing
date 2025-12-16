FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libreadline-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: lua" > /work/proj && \
    echo "version: 5.4.8" >> /work/proj && \
    echo "source: https://www.lua.org/ftp/lua-5.4.8.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.lua.org/ftp/lua-5.4.8.tar.gz && \
    tar -xzf lua-5.4.8.tar.gz && \
    rm lua-5.4.8.tar.gz && \
    cp -a lua-5.4.8 build-fuzz && \
    cp -a lua-5.4.8 build-cmplog && \
    cp -a lua-5.4.8 build-cov && \
    cp -a lua-5.4.8 build-uftrace && \
    rm -rf lua-5.4.8

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make -j$(nproc) \
    CC=afl-clang-lto \
    MYCFLAGS="-O2" \
    MYLDFLAGS="-static -Wl,--allow-multiple-definition" \
    linux

WORKDIR /work
RUN ln -s build-fuzz/src/lua bin-fuzz && \
    /work/bin-fuzz -v

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    MYCFLAGS="-O2" \
    MYLDFLAGS="-static -Wl,--allow-multiple-definition" \
    linux

WORKDIR /work
RUN ln -s build-cmplog/src/lua bin-cmplog && \
    /work/bin-cmplog -v

# Copy fuzzing resources
COPY lua/fuzz/dict /work/dict
COPY lua/fuzz/in /work/in
COPY lua/fuzz/fuzz.sh /work/fuzz.sh
COPY lua/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make -j$(nproc) \
    CC=clang \
    MYCFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    MYLDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    linux

WORKDIR /work
RUN ln -s build-cov/src/lua bin-cov && \
    /work/bin-cov -v && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make -j$(nproc) \
    CC=clang \
    MYCFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    MYLDFLAGS="-pg -Wl,--allow-multiple-definition" \
    linux && \
    make install INSTALL_TOP=/work/install-uftrace

WORKDIR /work
RUN ln -s install-uftrace/bin/lua bin-uftrace && \
    /work/bin-uftrace -v && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
