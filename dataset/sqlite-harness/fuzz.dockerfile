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
RUN wget https://github.com/sqlite/sqlite/archive/refs/tags/version-3.51.0.tar.gz && \
    tar -xzf version-3.51.0.tar.gz && \
    rm version-3.51.0.tar.gz

WORKDIR /src/sqlite-version-3.51.0

# Configure SQLite with static linking
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-tcl --disable-shared --enable-static

# Build SQLite amalgamation
RUN make sqlite3.c sqlite3.h -j$(nproc)

# Compile SQLite amalgamation with AFL++ instrumentation
RUN afl-clang-lto -O2 -c sqlite3.c -o sqlite3.o \
    -DSQLITE_OMIT_LOAD_EXTENSION

# Compile the OSS-Fuzz harness (test/ossfuzz.c)
RUN afl-clang-lto -O2 -c test/ossfuzz.c -o ossfuzz.o \
    -I.

# Link harness with SQLite and AFL++ fuzzer runtime
# Use -fsanitize=fuzzer to get the main function from libFuzzer-compatible AFL++
RUN afl-clang-lto -O2 \
    -fsanitize=fuzzer \
    -static -Wl,--allow-multiple-definition \
    ossfuzz.o sqlite3.o \
    -lpthread -lm -ldl \
    -o /out/sqlite_ossfuzz

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf sqlite-version-3.51.0 && \
    wget https://github.com/sqlite/sqlite/archive/refs/tags/version-3.51.0.tar.gz && \
    tar -xzf version-3.51.0.tar.gz && \
    rm version-3.51.0.tar.gz

WORKDIR /src/sqlite-version-3.51.0

# Configure with CMPLOG enabled
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-tcl --disable-shared --enable-static

# Build SQLite amalgamation with CMPLOG
RUN AFL_LLVM_CMPLOG=1 make sqlite3.c sqlite3.h -j$(nproc)

# Compile SQLite amalgamation with CMPLOG
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -c sqlite3.c -o sqlite3.o \
    -DSQLITE_OMIT_LOAD_EXTENSION

# Compile the OSS-Fuzz harness with CMPLOG
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -c test/ossfuzz.c -o ossfuzz.o \
    -I.

# Link CMPLOG version
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 \
    -fsanitize=fuzzer \
    -static -Wl,--allow-multiple-definition \
    ossfuzz.o sqlite3.o \
    -lpthread -lm -ldl \
    -o /out/sqlite_ossfuzz.cmplog

# Copy fuzzing resources
COPY dataset/sqlite-harness/fuzz/dict /out/dict
COPY dataset/sqlite-harness/fuzz/in /out/in
COPY dataset/sqlite-harness/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/sqlite-harness/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/sqlite_ossfuzz /out/sqlite_ossfuzz.cmplog && \
    file /out/sqlite_ossfuzz

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing sqlite_ossfuzz'"]
