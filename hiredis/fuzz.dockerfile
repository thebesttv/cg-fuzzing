FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract hiredis 1.3.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/redis/hiredis/archive/refs/tags/v1.3.0.tar.gz && \
    tar -xzf v1.3.0.tar.gz && \
    rm v1.3.0.tar.gz

WORKDIR /src/hiredis-1.3.0

# Create a harness for fuzzing the RESP protocol reader
# Save to /tmp for reuse in CMPLOG build
RUN echo '/* AFL++ fuzzer harness for hiredis RESP protocol reader */' > /tmp/fuzz_reader.c && \
    echo '#include <stdio.h>' >> /tmp/fuzz_reader.c && \
    echo '#include <stdlib.h>' >> /tmp/fuzz_reader.c && \
    echo '#include <string.h>' >> /tmp/fuzz_reader.c && \
    echo '#include <unistd.h>' >> /tmp/fuzz_reader.c && \
    echo '#include "hiredis.h"' >> /tmp/fuzz_reader.c && \
    echo '#include "read.h"' >> /tmp/fuzz_reader.c && \
    echo '' >> /tmp/fuzz_reader.c && \
    echo 'int main(int argc, char **argv) {' >> /tmp/fuzz_reader.c && \
    echo '    char buf[65536];' >> /tmp/fuzz_reader.c && \
    echo '    ssize_t len;' >> /tmp/fuzz_reader.c && \
    echo '    redisReader *reader;' >> /tmp/fuzz_reader.c && \
    echo '    void *reply;' >> /tmp/fuzz_reader.c && \
    echo '' >> /tmp/fuzz_reader.c && \
    echo '    if (argc > 1) {' >> /tmp/fuzz_reader.c && \
    echo '        FILE *f = fopen(argv[1], "rb");' >> /tmp/fuzz_reader.c && \
    echo '        if (!f) return 1;' >> /tmp/fuzz_reader.c && \
    echo '        len = fread(buf, 1, sizeof(buf), f);' >> /tmp/fuzz_reader.c && \
    echo '        fclose(f);' >> /tmp/fuzz_reader.c && \
    echo '    } else {' >> /tmp/fuzz_reader.c && \
    echo '        len = read(0, buf, sizeof(buf));' >> /tmp/fuzz_reader.c && \
    echo '    }' >> /tmp/fuzz_reader.c && \
    echo '' >> /tmp/fuzz_reader.c && \
    echo '    if (len <= 0) return 0;' >> /tmp/fuzz_reader.c && \
    echo '' >> /tmp/fuzz_reader.c && \
    echo '    reader = redisReaderCreate();' >> /tmp/fuzz_reader.c && \
    echo '    if (!reader) return 1;' >> /tmp/fuzz_reader.c && \
    echo '' >> /tmp/fuzz_reader.c && \
    echo '    if (redisReaderFeed(reader, buf, len) != REDIS_OK) {' >> /tmp/fuzz_reader.c && \
    echo '        redisReaderFree(reader);' >> /tmp/fuzz_reader.c && \
    echo '        return 0;' >> /tmp/fuzz_reader.c && \
    echo '    }' >> /tmp/fuzz_reader.c && \
    echo '' >> /tmp/fuzz_reader.c && \
    echo '    while (redisReaderGetReply(reader, &reply) == REDIS_OK) {' >> /tmp/fuzz_reader.c && \
    echo '        if (reply == NULL) break;' >> /tmp/fuzz_reader.c && \
    echo '        freeReplyObject(reply);' >> /tmp/fuzz_reader.c && \
    echo '    }' >> /tmp/fuzz_reader.c && \
    echo '' >> /tmp/fuzz_reader.c && \
    echo '    redisReaderFree(reader);' >> /tmp/fuzz_reader.c && \
    echo '    return 0;' >> /tmp/fuzz_reader.c && \
    echo '}' >> /tmp/fuzz_reader.c

# Copy harness to source directory
RUN cp /tmp/fuzz_reader.c .

# Build hiredis with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DDISABLE_TESTS=ON

RUN cd build && make -j$(nproc)

# Build the fuzzer harness
RUN afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    fuzz_reader.c \
    build/libhiredis.a \
    -o /out/fuzz_reader

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf hiredis-1.3.0 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/redis/hiredis/archive/refs/tags/v1.3.0.tar.gz && \
    tar -xzf v1.3.0.tar.gz && \
    rm v1.3.0.tar.gz

WORKDIR /src/hiredis-1.3.0

# Copy harness from /tmp (saved earlier)
RUN cp /tmp/fuzz_reader.c .

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DDISABLE_TESTS=ON

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build CMPLOG fuzzer harness
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    fuzz_reader.c \
    build/libhiredis.a \
    -o /out/fuzz_reader.cmplog

# Copy fuzzing resources
COPY hiredis/fuzz/dict /out/dict
COPY hiredis/fuzz/in /out/in
COPY hiredis/fuzz/fuzz.sh /out/fuzz.sh
COPY hiredis/fuzz/whatsup.sh /out/whatsup.sh

# Ensure scripts are executable
RUN chmod +x /out/fuzz.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/fuzz_reader /out/fuzz_reader.cmplog && \
    file /out/fuzz_reader

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing hiredis'"]
