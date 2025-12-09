FROM aflplusplus/aflplusplus:latest

RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /out

WORKDIR /src
RUN wget https://ftp.gnu.org/gnu/libunistring/libunistring-1.2.tar.gz && \
    tar -xzf libunistring-1.2.tar.gz && \
    rm libunistring-1.2.tar.gz

WORKDIR /src/libunistring-1.2

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
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

RUN afl-clang-lto -O2 test_unistring.c -o /out/test_unistring \
    -I. -I./lib lib/.libs/libunistring.a \
    -static -Wl,--allow-multiple-definition

WORKDIR /src
RUN rm -rf libunistring-1.2 && \
    wget https://ftp.gnu.org/gnu/libunistring/libunistring-1.2.tar.gz && \
    tar -xzf libunistring-1.2.tar.gz && \
    rm libunistring-1.2.tar.gz

WORKDIR /src/libunistring-1.2

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

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

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 test_unistring.c -o /out/test_unistring.cmplog \
    -I. -I./lib lib/.libs/libunistring.a \
    -static -Wl,--allow-multiple-definition

COPY libunistring/fuzz/dict /out/dict
COPY libunistring/fuzz/in /out/in
COPY libunistring/fuzz/fuzz.sh /out/fuzz.sh
COPY libunistring/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

RUN ls -la /out/test_unistring /out/test_unistring.cmplog && file /out/test_unistring

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libunistring'"]
