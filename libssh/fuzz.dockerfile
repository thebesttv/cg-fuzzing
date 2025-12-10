FROM aflplusplus/aflplusplus:latest

RUN apt-get update && \
    apt-get install -y wget cmake libssl-dev zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /out

WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://www.libssh.org/files/0.10/libssh-0.10.6.tar.xz && \
    tar -xf libssh-0.10.6.tar.xz && \
    rm libssh-0.10.6.tar.xz

WORKDIR /src/libssh-0.10.6

RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. -DCMAKE_C_FLAGS="-O2" \
             -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
             -DBUILD_SHARED_LIBS=OFF \
             -DWITH_EXAMPLES=OFF

RUN cd build && make -j$(nproc)

RUN echo '#include <libssh/libssh.h>' > test_ssh.c && \
    echo '#include <stdlib.h>' >> test_ssh.c && \
    echo '#include <unistd.h>' >> test_ssh.c && \
    echo '#include <fcntl.h>' >> test_ssh.c && \
    echo 'int main(int argc, char **argv) {' >> test_ssh.c && \
    echo '    if (argc < 2) return 1;' >> test_ssh.c && \
    echo '    int fd = open(argv[1], O_RDONLY);' >> test_ssh.c && \
    echo '    if (fd < 0) return 1;' >> test_ssh.c && \
    echo '    char buf[1024];' >> test_ssh.c && \
    echo '    ssize_t n = read(fd, buf, sizeof(buf));' >> test_ssh.c && \
    echo '    close(fd);' >> test_ssh.c && \
    echo '    if (n <= 0) return 1;' >> test_ssh.c && \
    echo '    ssh_session session = ssh_new();' >> test_ssh.c && \
    echo '    if (!session) return 1;' >> test_ssh.c && \
    echo '    ssh_free(session);' >> test_ssh.c && \
    echo '    return 0;' >> test_ssh.c && \
    echo '}' >> test_ssh.c

RUN afl-clang-lto -O2 test_ssh.c -o /out/test_ssh \
    -I./include -I./build/include build/src/libssh.a \
    -static -Wl,--allow-multiple-definition -lssl -lcrypto -lz -lpthread

WORKDIR /src
RUN rm -rf libssh-0.10.6 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://www.libssh.org/files/0.10/libssh-0.10.6.tar.xz && \
    tar -xf libssh-0.10.6.tar.xz && \
    rm libssh-0.10.6.tar.xz

WORKDIR /src/libssh-0.10.6

RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. -DCMAKE_C_FLAGS="-O2" \
             -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
             -DBUILD_SHARED_LIBS=OFF \
             -DWITH_EXAMPLES=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN echo '#include <libssh/libssh.h>' > test_ssh.c && \
    echo '#include <stdlib.h>' >> test_ssh.c && \
    echo '#include <unistd.h>' >> test_ssh.c && \
    echo '#include <fcntl.h>' >> test_ssh.c && \
    echo 'int main(int argc, char **argv) {' >> test_ssh.c && \
    echo '    if (argc < 2) return 1;' >> test_ssh.c && \
    echo '    int fd = open(argv[1], O_RDONLY);' >> test_ssh.c && \
    echo '    if (fd < 0) return 1;' >> test_ssh.c && \
    echo '    char buf[1024];' >> test_ssh.c && \
    echo '    ssize_t n = read(fd, buf, sizeof(buf));' >> test_ssh.c && \
    echo '    close(fd);' >> test_ssh.c && \
    echo '    if (n <= 0) return 1;' >> test_ssh.c && \
    echo '    ssh_session session = ssh_new();' >> test_ssh.c && \
    echo '    if (!session) return 1;' >> test_ssh.c && \
    echo '    ssh_free(session);' >> test_ssh.c && \
    echo '    return 0;' >> test_ssh.c && \
    echo '}' >> test_ssh.c

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 test_ssh.c -o /out/test_ssh.cmplog \
    -I./include -I./build/include build/src/libssh.a \
    -static -Wl,--allow-multiple-definition -lssl -lcrypto -lz -lpthread

COPY libssh/fuzz/dict /out/dict
COPY libssh/fuzz/in /out/in
COPY libssh/fuzz/fuzz.sh /out/fuzz.sh
COPY libssh/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

RUN ls -la /out/test_ssh /out/test_ssh.cmplog && file /out/test_ssh

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libssh'"]
