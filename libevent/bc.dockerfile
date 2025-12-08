FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libevent v2.1.12-stable
WORKDIR /home/SVF-tools
RUN wget https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz && \
    tar -xzf libevent-2.1.12-stable.tar.gz && \
    rm libevent-2.1.12-stable.tar.gz

WORKDIR /home/SVF-tools/libevent-2.1.12-stable

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static --disable-openssl

# Build libevent
RUN make -j$(nproc)

# Build a simple test program using libevent for fuzzing
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

RUN wllvm -g -O0 -Xclang -disable-llvm-passes \
    test_event.c -o test_event \
    -I./include -I. \
    .libs/libevent.a .libs/libevent_core.a \
    -static -Wl,--allow-multiple-definition -lpthread

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc test_event && \
    mv test_event.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
