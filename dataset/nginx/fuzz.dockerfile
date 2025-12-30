FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libpcre3-dev zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: nginx" > /work/proj && \
    echo "version: 1.29.4" >> /work/proj && \
    echo "source: https://nginx.org/download/nginx-1.29.4.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://nginx.org/download/nginx-1.29.4.tar.gz && \
    tar -xzf nginx-1.29.4.tar.gz && \
    rm nginx-1.29.4.tar.gz && \
    cp -a nginx-1.29.4 build-fuzz && \
    cp -a nginx-1.29.4 build-cmplog && \
    cp -a nginx-1.29.4 build-cov && \
    cp -a nginx-1.29.4 build-uftrace && \
    rm -rf nginx-1.29.4

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    ./configure --with-cc-opt="-O2" \
                --with-ld-opt="-static -Wl,--allow-multiple-definition" \
                --without-http_rewrite_module \
                --without-http_gzip_module && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/objs/nginx bin-fuzz && \
    /work/bin-fuzz -V

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --with-cc-opt="-O2" \
                --with-ld-opt="-static -Wl,--allow-multiple-definition" \
                --without-http_rewrite_module \
                --without-http_gzip_module && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/objs/nginx bin-cmplog && \
    /work/bin-cmplog -V

# Copy fuzzing resources
COPY nginx/fuzz/dict /work/dict
COPY nginx/fuzz/in /work/in
COPY nginx/fuzz/fuzz.sh /work/fuzz.sh
COPY nginx/fuzz/whatsup.sh /work/whatsup.sh
COPY nginx/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY nginx/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY nginx/fuzz/collect-branch.py /work/collect-branch.py
COPY nginx/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY nginx/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    ./configure --with-cc-opt="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
                --with-ld-opt="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
                --without-http_rewrite_module \
                --without-http_gzip_module && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/objs/nginx bin-cov && \
    /work/bin-cov -V && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    ./configure --with-cc-opt="-g -O0 -pg -fno-omit-frame-pointer" \
                --with-ld-opt="-pg -Wl,--allow-multiple-definition" \
                --without-http_rewrite_module \
                --without-http_gzip_module \
                --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/sbin/nginx bin-uftrace && \
    /work/bin-uftrace -V && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
