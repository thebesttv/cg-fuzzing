FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libuv v1.48.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/libuv/libuv/archive/refs/tags/v1.48.0.tar.gz && \
    tar -xzf v1.48.0.tar.gz && \
    rm v1.48.0.tar.gz

WORKDIR /src/libuv-1.48.0

# Generate configure script
RUN ./autogen.sh

# Build libuv with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Build a simple test program for fuzzing
RUN echo '#include <uv.h>' > test_uv.c && \
    echo '#include <stdio.h>' >> test_uv.c && \
    echo '#include <stdlib.h>' >> test_uv.c && \
    echo '#include <string.h>' >> test_uv.c && \
    echo '#include <fcntl.h>' >> test_uv.c && \
    echo '#include <unistd.h>' >> test_uv.c && \
    echo 'int main(int argc, char **argv) {' >> test_uv.c && \
    echo '    if (argc < 2) return 1;' >> test_uv.c && \
    echo '    int fd = open(argv[1], O_RDONLY);' >> test_uv.c && \
    echo '    if (fd < 0) return 1;' >> test_uv.c && \
    echo '    char buf[4096];' >> test_uv.c && \
    echo '    ssize_t n = read(fd, buf, sizeof(buf));' >> test_uv.c && \
    echo '    close(fd);' >> test_uv.c && \
    echo '    if (n <= 0) return 1;' >> test_uv.c && \
    echo '    uv_loop_t *loop = uv_default_loop();' >> test_uv.c && \
    echo '    if (!loop) return 1;' >> test_uv.c && \
    echo '    uv_run(loop, UV_RUN_DEFAULT);' >> test_uv.c && \
    echo '    uv_loop_close(loop);' >> test_uv.c && \
    echo '    return 0;' >> test_uv.c && \
    echo '}' >> test_uv.c

RUN afl-clang-lto -O2 \
    test_uv.c -o test_uv \
    -I./include -I./src \
    .libs/libuv.a \
    -static -Wl,--allow-multiple-definition -lpthread

RUN cp test_uv /out/test_uv

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf libuv-1.48.0 && \
    wget https://github.com/libuv/libuv/archive/refs/tags/v1.48.0.tar.gz && \
    tar -xzf v1.48.0.tar.gz && \
    rm v1.48.0.tar.gz

WORKDIR /src/libuv-1.48.0

RUN ./autogen.sh

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build CMPLOG test program
RUN echo '#include <uv.h>' > test_uv.c && \
    echo '#include <stdio.h>' >> test_uv.c && \
    echo '#include <stdlib.h>' >> test_uv.c && \
    echo '#include <string.h>' >> test_uv.c && \
    echo '#include <fcntl.h>' >> test_uv.c && \
    echo '#include <unistd.h>' >> test_uv.c && \
    echo 'int main(int argc, char **argv) {' >> test_uv.c && \
    echo '    if (argc < 2) return 1;' >> test_uv.c && \
    echo '    int fd = open(argv[1], O_RDONLY);' >> test_uv.c && \
    echo '    if (fd < 0) return 1;' >> test_uv.c && \
    echo '    char buf[4096];' >> test_uv.c && \
    echo '    ssize_t n = read(fd, buf, sizeof(buf));' >> test_uv.c && \
    echo '    close(fd);' >> test_uv.c && \
    echo '    if (n <= 0) return 1;' >> test_uv.c && \
    echo '    uv_loop_t *loop = uv_default_loop();' >> test_uv.c && \
    echo '    if (!loop) return 1;' >> test_uv.c && \
    echo '    uv_run(loop, UV_RUN_DEFAULT);' >> test_uv.c && \
    echo '    uv_loop_close(loop);' >> test_uv.c && \
    echo '    return 0;' >> test_uv.c && \
    echo '}' >> test_uv.c

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 \
    test_uv.c -o test_uv_cmplog \
    -I./include -I./src \
    .libs/libuv.a \
    -static -Wl,--allow-multiple-definition -lpthread

RUN cp test_uv_cmplog /out/test_uv.cmplog

# Copy fuzzing resources
COPY dataset/libuv/fuzz/dict /out/dict
COPY dataset/libuv/fuzz/in /out/in
COPY dataset/libuv/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libuv/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/test_uv /out/test_uv.cmplog && \
    file /out/test_uv

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libuv'"]
