FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract lmdb 0.9.31 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/LMDB/lmdb/archive/refs/tags/LMDB_0.9.31.tar.gz && \
    tar -xzf LMDB_0.9.31.tar.gz && \
    rm LMDB_0.9.31.tar.gz

WORKDIR /src/lmdb-LMDB_0.9.31/libraries/liblmdb

# Build lmdb with afl-clang-lto for fuzzing
RUN make CC=afl-clang-lto \
    CFLAGS="-O2 -pthread" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -pthread" \
    mdb_load -j$(nproc)

RUN cp mdb_load /out/mdb_load

# Build CMPLOG version
WORKDIR /src
RUN rm -rf lmdb-LMDB_0.9.31 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/LMDB/lmdb/archive/refs/tags/LMDB_0.9.31.tar.gz && \
    tar -xzf LMDB_0.9.31.tar.gz && \
    rm LMDB_0.9.31.tar.gz

WORKDIR /src/lmdb-LMDB_0.9.31/libraries/liblmdb

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2 -pthread" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -pthread" \
    mdb_load -j$(nproc)

RUN cp mdb_load /out/mdb_load.cmplog

# Copy fuzzing resources
COPY lmdb/fuzz/dict /out/dict
COPY lmdb/fuzz/in /out/in
COPY lmdb/fuzz/fuzz.sh /out/fuzz.sh
COPY lmdb/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/mdb_load /out/mdb_load.cmplog && \
    file /out/mdb_load

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing mdb_load'"]
