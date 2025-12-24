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
RUN echo "project: libpng" > /work/proj && \
    echo "version: 1.6.47" >> /work/proj && \
    echo "source: https://download.sourceforge.net/libpng/libpng-1.6.47.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.sourceforge.net/libpng/libpng-1.6.47.tar.gz && \
    tar -xzf libpng-1.6.47.tar.gz && \
    rm libpng-1.6.47.tar.gz && \
    cp -a libpng-1.6.47 build-fuzz && \
    cp -a libpng-1.6.47 build-cmplog && \
    cp -a libpng-1.6.47 build-cov && \
    cp -a libpng-1.6.47 build-uftrace && \
    rm -rf libpng-1.6.47

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

# Build png2pnm (the CLI tool for fuzzing)
WORKDIR /work/build-fuzz/contrib/pngminus
RUN afl-clang-lto -O2 -I../.. -L../../.libs png2pnm.c -o png2pnm -lpng16 -lz -lm \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-fuzz/contrib/pngminus/png2pnm bin-fuzz && \
    /work/bin-fuzz /work/build-fuzz/pngtest.png > /dev/null

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build CMPLOG version of png2pnm
WORKDIR /work/build-cmplog/contrib/pngminus
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I../.. -L../../.libs png2pnm.c -o png2pnm \
    -lpng16 -lz -lm -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cmplog/contrib/pngminus/png2pnm bin-cmplog && \
    /work/bin-cmplog /work/build-cmplog/pngtest.png > /dev/null

# Copy fuzzing resources
COPY libpng/fuzz/dict /work/dict
COPY libpng/fuzz/in /work/in
COPY libpng/fuzz/fuzz.sh /work/fuzz.sh
COPY libpng/fuzz/whatsup.sh /work/whatsup.sh
COPY libpng/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libpng/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libpng/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

# Build cov version of png2pnm
WORKDIR /work/build-cov/contrib/pngminus
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I../.. -L../../.libs png2pnm.c -o png2pnm \
    -lpng16 -lz -lm -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cov/contrib/pngminus/png2pnm bin-cov && \
    /work/bin-cov /work/build-cov/pngtest.png > /dev/null && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

# Build uftrace version of png2pnm
WORKDIR /work/build-uftrace/contrib/pngminus
RUN clang -g -O0 -pg -fno-omit-frame-pointer -I../.. -L../../.libs png2pnm.c -o png2pnm \
    -lpng16 -lz -lm -pg -Wl,--allow-multiple-definition && \
    mkdir -p /work/install-uftrace/bin && \
    cp png2pnm /work/install-uftrace/bin/

WORKDIR /work
RUN ln -s install-uftrace/bin/png2pnm bin-uftrace && \
    /work/bin-uftrace /work/build-uftrace/pngtest.png > /dev/null && \
    uftrace record /work/bin-uftrace /work/build-uftrace/pngtest.png > /dev/null && \
    uftrace report && \
    rm -rf uftrace.data gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
