FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract SQLite version-3.51.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/sqlite/sqlite/archive/refs/tags/version-3.51.0.tar.gz && \
    tar -xzf version-3.51.0.tar.gz && \
    rm version-3.51.0.tar.gz

WORKDIR /src/sqlite-version-3.51.0

# Build sqlite3 with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-tcl --disable-shared --enable-static

RUN make sqlite3 -j$(nproc)

# Install the sqlite3 binary
RUN cp sqlite3 /out/sqlite3

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf sqlite-version-3.51.0 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/sqlite/sqlite/archive/refs/tags/version-3.51.0.tar.gz && \
    tar -xzf version-3.51.0.tar.gz && \
    rm version-3.51.0.tar.gz

WORKDIR /src/sqlite-version-3.51.0

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-tcl --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make sqlite3 -j$(nproc)

# Install CMPLOG binary
RUN cp sqlite3 /out/sqlite3.cmplog

# Copy fuzzing resources
COPY sqlite/fuzz/dict /out/dict
COPY sqlite/fuzz/in /out/in
COPY sqlite/fuzz/fuzz.sh /out/fuzz.sh
COPY sqlite/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/sqlite3 /out/sqlite3.cmplog && \
    file /out/sqlite3 && \
    /out/sqlite3 --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing sqlite3'"]
