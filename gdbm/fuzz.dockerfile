FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract gdbm 1.26 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/gdbm/gdbm-1.26.tar.gz && \
    tar -xzf gdbm-1.26.tar.gz && \
    rm gdbm-1.26.tar.gz

WORKDIR /src/gdbm-1.26

# Build gdbm with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --without-readline

RUN make -j$(nproc)
RUN cp tools/gdbm_load /out/gdbm_load

# Build CMPLOG version
WORKDIR /src
RUN rm -rf gdbm-1.26 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/gdbm/gdbm-1.26.tar.gz && \
    tar -xzf gdbm-1.26.tar.gz && \
    rm gdbm-1.26.tar.gz

WORKDIR /src/gdbm-1.26

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --without-readline

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp tools/gdbm_load /out/gdbm_load.cmplog

# Copy fuzzing resources
COPY gdbm/fuzz/dict /out/dict
COPY gdbm/fuzz/in /out/in
COPY gdbm/fuzz/fuzz.sh /out/fuzz.sh
COPY gdbm/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/gdbm_load /out/gdbm_load.cmplog && \
    file /out/gdbm_load

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing gdbm_load'"]
