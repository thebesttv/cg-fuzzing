FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libconfig v1.7.3 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/hyperrealm/libconfig/releases/download/v1.7.3/libconfig-1.7.3.tar.gz && \
    tar -xzf libconfig-1.7.3.tar.gz && \
    rm libconfig-1.7.3.tar.gz

WORKDIR /src/libconfig-1.7.3

# Build libconfig with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Build a simple test harness that parses config files
RUN echo '#include <stdio.h>\n#include <libconfig.h>\nint main(int argc, char **argv) { config_t cfg; config_init(&cfg); if(argc > 1) config_read_file(&cfg, argv[1]); config_destroy(&cfg); return 0; }' > /tmp/harness.c && \
    afl-clang-lto -O2 -I./lib /tmp/harness.c -L./lib/.libs -lconfig -static -Wl,--allow-multiple-definition -o /out/config_parse

# Build CMPLOG version
WORKDIR /src
RUN rm -rf libconfig-1.7.3 && \
    wget https://github.com/hyperrealm/libconfig/releases/download/v1.7.3/libconfig-1.7.3.tar.gz && \
    tar -xzf libconfig-1.7.3.tar.gz && \
    rm libconfig-1.7.3.tar.gz

WORKDIR /src/libconfig-1.7.3

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN echo '#include <stdio.h>\n#include <libconfig.h>\nint main(int argc, char **argv) { config_t cfg; config_init(&cfg); if(argc > 1) config_read_file(&cfg, argv[1]); config_destroy(&cfg); return 0; }' > /tmp/harness.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I./lib /tmp/harness.c -L./lib/.libs -lconfig -static -Wl,--allow-multiple-definition -o /out/config_parse.cmplog

# Copy fuzzing resources
COPY dataset/libconfig/fuzz/dict /out/dict
COPY dataset/libconfig/fuzz/in /out/in
COPY dataset/libconfig/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libconfig/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/config_parse /out/config_parse.cmplog && \
    file /out/config_parse

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libconfig'"]
