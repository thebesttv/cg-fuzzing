FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libuv v1.48.0
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/libuv/libuv/archive/refs/tags/v1.48.0.tar.gz && \
    tar -xzf v1.48.0.tar.gz && \
    rm v1.48.0.tar.gz

WORKDIR /home/SVF-tools/libuv-1.48.0

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Generate configure script
RUN ./autogen.sh

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static

# Build libuv
RUN make -j$(nproc)

# Build a simple test program using libuv for fuzzing
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

RUN wllvm -g -O0 -Xclang -disable-llvm-passes \
    test_uv.c -o test_uv \
    -I./include -I./src \
    .libs/libuv.a \
    -static -Wl,--allow-multiple-definition -lpthread

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc test_uv && \
    mv test_uv.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
