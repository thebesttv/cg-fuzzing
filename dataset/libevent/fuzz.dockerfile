FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libssl-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libevent" > /work/proj && \
    echo "version: 2.1.12-stable" >> /work/proj && \
    echo "source: https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz" >> /work/proj

# Create harness source once
RUN echo '#include <event2/event.h>' > /work/test_event.c && \
    echo '#include <stdio.h>' >> /work/test_event.c && \
    echo '#include <stdlib.h>' >> /work/test_event.c && \
    echo '#include <string.h>' >> /work/test_event.c && \
    echo '#include <fcntl.h>' >> /work/test_event.c && \
    echo '#include <unistd.h>' >> /work/test_event.c && \
    echo 'int main(int argc, char **argv) {' >> /work/test_event.c && \
    echo '    if (argc < 2) return 1;' >> /work/test_event.c && \
    echo '    int fd = open(argv[1], O_RDONLY);' >> /work/test_event.c && \
    echo '    if (fd < 0) return 1;' >> /work/test_event.c && \
    echo '    char buf[4096];' >> /work/test_event.c && \
    echo '    ssize_t n = read(fd, buf, sizeof(buf));' >> /work/test_event.c && \
    echo '    close(fd);' >> /work/test_event.c && \
    echo '    if (n <= 0) return 1;' >> /work/test_event.c && \
    echo '    struct event_base *base = event_base_new();' >> /work/test_event.c && \
    echo '    if (!base) return 1;' >> /work/test_event.c && \
    echo '    event_base_free(base);' >> /work/test_event.c && \
    echo '    return 0;' >> /work/test_event.c && \
    echo '}' >> /work/test_event.c

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz && \
    tar -xzf libevent-2.1.12-stable.tar.gz && \
    rm libevent-2.1.12-stable.tar.gz && \
    cp -a libevent-2.1.12-stable build-fuzz && \
    cp -a libevent-2.1.12-stable build-cmplog && \
    cp -a libevent-2.1.12-stable build-cov && \
    cp -a libevent-2.1.12-stable build-uftrace && \
    rm -rf libevent-2.1.12-stable

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-openssl && \
    make -j$(nproc)

RUN afl-clang-lto -O2 /work/test_event.c -o test_event \
    -I./include -I. .libs/libevent.a .libs/libevent_core.a \
    -static -Wl,--allow-multiple-definition -lpthread

WORKDIR /work
RUN ln -s build-fuzz/test_event bin-fuzz && \
    /work/bin-fuzz /dev/null || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --disable-openssl && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 /work/test_event.c -o test_event \
    -I./include -I. .libs/libevent.a .libs/libevent_core.a \
    -static -Wl,--allow-multiple-definition -lpthread

WORKDIR /work
RUN ln -s build-cmplog/test_event bin-cmplog && \
    /work/bin-cmplog /dev/null || true

# Copy fuzzing resources
COPY libevent/fuzz/dict /work/dict
COPY libevent/fuzz/in /work/in
COPY libevent/fuzz/fuzz.sh /work/fuzz.sh
COPY libevent/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-openssl && \
    make -j$(nproc)

RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping /work/test_event.c -o test_event \
    -I./include -I. .libs/libevent.a .libs/libevent_core.a \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition -lpthread

WORKDIR /work
RUN ln -s build-cov/test_event bin-cov && \
    /work/bin-cov /dev/null || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-openssl --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

RUN clang -g -O0 -pg -fno-omit-frame-pointer /work/test_event.c -o /work/install-uftrace/bin/test_event \
    -I./include -I. .libs/libevent.a .libs/libevent_core.a \
    -pg -Wl,--allow-multiple-definition -lpthread

WORKDIR /work
RUN ln -s install-uftrace/bin/test_event bin-uftrace && \
    /work/bin-uftrace /dev/null || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
