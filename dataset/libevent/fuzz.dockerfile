FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libevent v2.1.12-stable (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz && \
    tar -xzf libevent-2.1.12-stable.tar.gz && \
    rm libevent-2.1.12-stable.tar.gz

WORKDIR /src/libevent-2.1.12-stable

# Build libevent with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-openssl

RUN make -j$(nproc)

# Build a simple test program for fuzzing
RUN echo '#include <event2/event.h>' > test_event.c && \
    echo '#include <stdio.h>' >> test_event.c && \
    echo '#include <stdlib.h>' >> test_event.c && \
    echo '#include <string.h>' >> test_event.c && \
    echo '#include <fcntl.h>' >> test_event.c && \
    echo '#include <unistd.h>' >> test_event.c && \
    echo 'int main(int argc, char **argv) {' >> test_event.c && \
    echo '    if (argc < 2) return 1;' >> test_event.c && \
    echo '    int fd = open(argv[1], O_RDONLY);' >> test_event.c && \
    echo '    if (fd < 0) return 1;' >> test_event.c && \
    echo '    char buf[4096];' >> test_event.c && \
    echo '    ssize_t n = read(fd, buf, sizeof(buf));' >> test_event.c && \
    echo '    close(fd);' >> test_event.c && \
    echo '    if (n <= 0) return 1;' >> test_event.c && \
    echo '    struct event_base *base = event_base_new();' >> test_event.c && \
    echo '    if (!base) return 1;' >> test_event.c && \
    echo '    event_base_free(base);' >> test_event.c && \
    echo '    return 0;' >> test_event.c && \
    echo '}' >> test_event.c

RUN afl-clang-lto -O2 \
    test_event.c -o test_event \
    -I./include -I. \
    .libs/libevent.a .libs/libevent_core.a \
    -static -Wl,--allow-multiple-definition -lpthread

RUN cp test_event /out/test_event

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf libevent-2.1.12-stable && \
    wget https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz && \
    tar -xzf libevent-2.1.12-stable.tar.gz && \
    rm libevent-2.1.12-stable.tar.gz

WORKDIR /src/libevent-2.1.12-stable

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --disable-openssl

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build CMPLOG test program
RUN echo '#include <event2/event.h>' > test_event.c && \
    echo '#include <stdio.h>' >> test_event.c && \
    echo '#include <stdlib.h>' >> test_event.c && \
    echo '#include <string.h>' >> test_event.c && \
    echo '#include <fcntl.h>' >> test_event.c && \
    echo '#include <unistd.h>' >> test_event.c && \
    echo 'int main(int argc, char **argv) {' >> test_event.c && \
    echo '    if (argc < 2) return 1;' >> test_event.c && \
    echo '    int fd = open(argv[1], O_RDONLY);' >> test_event.c && \
    echo '    if (fd < 0) return 1;' >> test_event.c && \
    echo '    char buf[4096];' >> test_event.c && \
    echo '    ssize_t n = read(fd, buf, sizeof(buf));' >> test_event.c && \
    echo '    close(fd);' >> test_event.c && \
    echo '    if (n <= 0) return 1;' >> test_event.c && \
    echo '    struct event_base *base = event_base_new();' >> test_event.c && \
    echo '    if (!base) return 1;' >> test_event.c && \
    echo '    event_base_free(base);' >> test_event.c && \
    echo '    return 0;' >> test_event.c && \
    echo '}' >> test_event.c

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 \
    test_event.c -o test_event_cmplog \
    -I./include -I. \
    .libs/libevent.a .libs/libevent_core.a \
    -static -Wl,--allow-multiple-definition -lpthread

RUN cp test_event_cmplog /out/test_event.cmplog

# Copy fuzzing resources
COPY dataset/libevent/fuzz/dict /out/dict
COPY dataset/libevent/fuzz/in /out/in
COPY dataset/libevent/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libevent/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/test_event /out/test_event.cmplog && \
    file /out/test_event

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libevent'"]
