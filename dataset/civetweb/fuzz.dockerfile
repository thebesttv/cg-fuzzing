FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libssl-dev zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract civetweb v1.16 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/civetweb/civetweb/archive/refs/tags/v1.16.tar.gz && \
    tar -xzf v1.16.tar.gz && \
    rm v1.16.tar.gz

WORKDIR /src/civetweb-1.16

# Build library with afl-clang-lto (without SSL for simpler harness)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -DNO_SSL" \
    make lib

# Copy harness and compile (include civetweb.c directly for static functions)
COPY dataset/civetweb/fuzz/harness/afl_http.c /src/afl_http.c
RUN afl-clang-lto -O2 -I/src/civetweb-1.16/include -I/src/civetweb-1.16/src \
    -D_GNU_SOURCE -DNO_SSL -DUSE_IPV6 -DUSE_WEBSOCKET -DMG_EXPERIMENTAL_INTERFACES \
    /src/afl_http.c \
    -o /out/civetweb_url_fuzz \
    -lpthread -ldl

# Build CMPLOG version
WORKDIR /src
RUN rm -rf civetweb-1.16 && \
    wget https://github.com/civetweb/civetweb/archive/refs/tags/v1.16.tar.gz && \
    tar -xzf v1.16.tar.gz && \
    rm v1.16.tar.gz

WORKDIR /src/civetweb-1.16

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -DNO_SSL" \
    AFL_LLVM_CMPLOG=1 \
    make lib

# Compile CMPLOG harness
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I/src/civetweb-1.16/include -I/src/civetweb-1.16/src \
    -D_GNU_SOURCE -DNO_SSL -DUSE_IPV6 -DUSE_WEBSOCKET -DMG_EXPERIMENTAL_INTERFACES \
    /src/afl_http.c \
    -o /out/civetweb_url_fuzz.cmplog \
    -lpthread -ldl

# Copy fuzzing resources
COPY dataset/civetweb/fuzz/dict /out/dict
COPY dataset/civetweb/fuzz/in /out/in
COPY dataset/civetweb/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/civetweb/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/civetweb_url_fuzz /out/civetweb_url_fuzz.cmplog && \
    file /out/civetweb_url_fuzz

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing civetweb'"]
