FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libssl-dev pkg-config uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: wget" > /work/proj && \
    echo "version: 1.24.5" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/wget/wget-1.24.5.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/wget/wget-1.24.5.tar.gz && \
    tar -xzf wget-1.24.5.tar.gz && \
    rm wget-1.24.5.tar.gz && \
    cp -a wget-1.24.5 build-fuzz && \
    cp -a wget-1.24.5 build-cmplog && \
    cp -a wget-1.24.5 build-cov && \
    cp -a wget-1.24.5 build-uftrace && \
    rm -rf wget-1.24.5

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --with-ssl=openssl --disable-nls && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/wget bin-fuzz && \
    /work/bin-fuzz --version | head -5

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --with-ssl=openssl --disable-nls && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/wget bin-cmplog && \
    /work/bin-cmplog --version | head -5

# Copy fuzzing resources
COPY wget/fuzz/dict /work/dict
COPY wget/fuzz/in /work/in
COPY wget/fuzz/fuzz.sh /work/fuzz.sh
COPY wget/fuzz/whatsup.sh /work/whatsup.sh
COPY wget/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY wget/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY wget/fuzz/collect-branch.py /work/collect-branch.py
COPY wget/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --with-ssl=openssl --disable-nls && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/wget bin-cov && \
    /work/bin-cov --version | head -5 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --prefix=/work/install-uftrace --disable-shared --with-ssl=openssl --disable-nls && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/wget bin-uftrace && \
    /work/bin-uftrace --version | head -5 && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
