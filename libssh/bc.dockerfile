FROM svftools/svf:latest

RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://www.libssh.org/files/0.10/libssh-0.10.6.tar.xz && \
    tar -xf libssh-0.10.6.tar.xz && \
    rm libssh-0.10.6.tar.xz

WORKDIR /home/SVF-tools/libssh-0.10.6

RUN apt-get update && \
    apt-get install -y file cmake libssl-dev zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
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

RUN wllvm -g -O0 -Xclang -disable-llvm-passes \
    test_ssh.c -o test_ssh \
    -I./include -I./build/include \
    build/src/libssh.a \
    -static -Wl,--allow-multiple-definition -lssl -lcrypto -lz -lpthread

RUN mkdir -p ~/bc && \
    extract-bc test_ssh && \
    mv test_ssh.bc ~/bc/

RUN ls -la ~/bc/
