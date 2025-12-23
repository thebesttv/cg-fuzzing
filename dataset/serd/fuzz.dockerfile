FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget meson python3-pip ninja-build uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: serd" > /work/proj && \
    echo "version: 0.32.2" >> /work/proj && \
    echo "source: https://gitlab.com/drobilla/serd/-/archive/v0.32.2/serd-v0.32.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 \
    https://gitlab.com/drobilla/serd/-/archive/v0.32.2/serd-v0.32.2.tar.gz && \
    tar -xzf serd-v0.32.2.tar.gz && \
    rm serd-v0.32.2.tar.gz && \
    cp -a serd-v0.32.2 build-fuzz && \
    cp -a serd-v0.32.2 build-cmplog && \
    cp -a serd-v0.32.2 build-cov && \
    cp -a serd-v0.32.2 build-uftrace && \
    rm -rf serd-v0.32.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    meson setup build \
    --default-library=static \
    -Ddocs=disabled \
    -Dtools=enabled \
    -Dtests=disabled && \
    ninja -C build

WORKDIR /work
RUN ln -s build-fuzz/build/serdi bin-fuzz && \
    /work/bin-fuzz --help | head -5 || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    meson setup build \
    --default-library=static \
    -Ddocs=disabled \
    -Dtools=enabled \
    -Dtests=disabled && \
    AFL_LLVM_CMPLOG=1 ninja -C build

WORKDIR /work
RUN ln -s build-cmplog/build/serdi bin-cmplog && \
    /work/bin-cmplog --help | head -5 || true

# Copy fuzzing resources
COPY serd/fuzz/dict /work/dict
COPY serd/fuzz/in /work/in
COPY serd/fuzz/fuzz.sh /work/fuzz.sh
COPY serd/fuzz/whatsup.sh /work/whatsup.sh
COPY serd/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    meson setup build \
    --default-library=static \
    -Ddocs=disabled \
    -Dtools=enabled \
    -Dtests=disabled && \
    ninja -C build

WORKDIR /work
RUN ln -s build-cov/build/serdi bin-cov && \
    /work/bin-cov --help | head -5 || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    meson setup build \
    --prefix=/work/install-uftrace \
    --default-library=static \
    -Ddocs=disabled \
    -Dtools=enabled \
    -Dtests=disabled && \
    ninja -C build && \
    ninja -C build install

WORKDIR /work
RUN ln -s install-uftrace/bin/serdi bin-uftrace && \
    /work/bin-uftrace --help | head -5 || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
