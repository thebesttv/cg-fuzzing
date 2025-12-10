FROM svftools/svf:latest

RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/libunistring/libunistring-1.2.tar.gz && \
    tar -xzf libunistring-1.2.tar.gz && \
    rm libunistring-1.2.tar.gz

WORKDIR /home/SVF-tools/libunistring-1.2

RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

RUN echo '#include "config.h"' > test_unistring.c && \
    echo '#include <unistr.h>' >> test_unistring.c && \
    echo '#include <stdlib.h>' >> test_unistring.c && \
    echo '#include <unistd.h>' >> test_unistring.c && \
    echo '#include <fcntl.h>' >> test_unistring.c && \
    echo 'int main(int argc, char **argv) {' >> test_unistring.c && \
    echo '    if (argc < 2) return 1;' >> test_unistring.c && \
    echo '    int fd = open(argv[1], O_RDONLY);' >> test_unistring.c && \
    echo '    if (fd < 0) return 1;' >> test_unistring.c && \
    echo '    uint8_t buf[1024];' >> test_unistring.c && \
    echo '    ssize_t n = read(fd, buf, sizeof(buf));' >> test_unistring.c && \
    echo '    close(fd);' >> test_unistring.c && \
    echo '    if (n <= 0) return 1;' >> test_unistring.c && \
    echo '    u8_check(buf, n);' >> test_unistring.c && \
    echo '    return 0;' >> test_unistring.c && \
    echo '}' >> test_unistring.c

RUN wllvm -g -O0 -Xclang -disable-llvm-passes \
    test_unistring.c -o test_unistring \
    -I./lib lib/.libs/libunistring.a \
    -static -Wl,--allow-multiple-definition

RUN mkdir -p ~/bc && \
    extract-bc test_unistring && \
    mv test_unistring.bc ~/bc/

RUN ls -la ~/bc/
