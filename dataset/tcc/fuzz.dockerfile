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
RUN echo "project: tcc" > /work/proj && \
    echo "version: 0.9.27" >> /work/proj && \
    echo "source: https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27.tar.bz2" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27.tar.bz2 && \
    tar -xjf tcc-0.9.27.tar.bz2 && \
    rm tcc-0.9.27.tar.bz2 && \
    cp -a tcc-0.9.27 build-fuzz && \
    cp -a tcc-0.9.27 build-cmplog && \
    cp -a tcc-0.9.27 build-cov && \
    cp -a tcc-0.9.27 build-uftrace && \
    rm -rf tcc-0.9.27

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./configure --prefix=/usr/local --disable-bcheck \
    --cc=afl-clang-lto \
    --extra-cflags="-O2" \
    --extra-ldflags="-static -Wl,--allow-multiple-definition" && \
    make tcc -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/tcc bin-fuzz && \
    /work/bin-fuzz -v

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 ./configure --prefix=/usr/local --disable-bcheck \
    --cc=afl-clang-lto \
    --extra-cflags="-O2" \
    --extra-ldflags="-static -Wl,--allow-multiple-definition" && \
    AFL_LLVM_CMPLOG=1 make tcc -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/tcc bin-cmplog && \
    /work/bin-cmplog -v

# Copy fuzzing resources
COPY tcc/fuzz/dict /work/dict
COPY tcc/fuzz/in /work/in
COPY tcc/fuzz/fuzz.sh /work/fuzz.sh
COPY tcc/fuzz/whatsup.sh /work/whatsup.sh
COPY tcc/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./configure --prefix=/usr/local --disable-bcheck \
    --cc=clang \
    --extra-cflags="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    --extra-ldflags="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" && \
    make tcc -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/tcc bin-cov && \
    /work/bin-cov -v && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./configure --prefix=/usr/local --disable-bcheck \
    --cc=clang \
    --extra-cflags="-g -O0 -pg -fno-omit-frame-pointer" \
    --extra-ldflags="-pg -Wl,--allow-multiple-definition" && \
    make tcc -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/tcc bin-uftrace && \
    /work/bin-uftrace -v && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
