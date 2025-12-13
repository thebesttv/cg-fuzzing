FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake libssl-dev zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libssh" > /work/proj && \
    echo "version: 0.10.6" >> /work/proj && \
    echo "source: https://www.libssh.org/files/0.10/libssh-0.10.6.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.libssh.org/files/0.10/libssh-0.10.6.tar.xz && \
    tar -xf libssh-0.10.6.tar.xz && \
    rm libssh-0.10.6.tar.xz && \
    cp -a libssh-0.10.6 build-fuzz && \
    cp -a libssh-0.10.6 build-cmplog && \
    cp -a libssh-0.10.6 build-cov && \
    cp -a libssh-0.10.6 build-uftrace && \
    rm -rf libssh-0.10.6

# Create test harness source
RUN echo '#include <libssh/libssh.h>' > /work/test_ssh.c && \
    echo '#include <stdlib.h>' >> /work/test_ssh.c && \
    echo '#include <unistd.h>' >> /work/test_ssh.c && \
    echo '#include <fcntl.h>' >> /work/test_ssh.c && \
    echo 'int main(int argc, char **argv) {' >> /work/test_ssh.c && \
    echo '    if (argc < 2) return 1;' >> /work/test_ssh.c && \
    echo '    int fd = open(argv[1], O_RDONLY);' >> /work/test_ssh.c && \
    echo '    if (fd < 0) return 1;' >> /work/test_ssh.c && \
    echo '    char buf[1024];' >> /work/test_ssh.c && \
    echo '    ssize_t n = read(fd, buf, sizeof(buf));' >> /work/test_ssh.c && \
    echo '    close(fd);' >> /work/test_ssh.c && \
    echo '    if (n <= 0) return 1;' >> /work/test_ssh.c && \
    echo '    ssh_session session = ssh_new();' >> /work/test_ssh.c && \
    echo '    if (!session) return 1;' >> /work/test_ssh.c && \
    echo '    ssh_free(session);' >> /work/test_ssh.c && \
    echo '    return 0;' >> /work/test_ssh.c && \
    echo '}' >> /work/test_ssh.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. -DCMAKE_C_FLAGS="-O2" \
             -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
             -DBUILD_SHARED_LIBS=OFF \
             -DWITH_EXAMPLES=OFF && \
    make -j$(nproc)

RUN afl-clang-lto -O2 /work/test_ssh.c -o test_ssh \
    -I./include -I./build/include build/src/libssh.a \
    -static -Wl,--allow-multiple-definition -lssl -lcrypto -lz -lpthread

WORKDIR /work
RUN ln -s build-fuzz/test_ssh bin-fuzz && \
    /work/bin-fuzz /work/test_ssh.c || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. -DCMAKE_C_FLAGS="-O2" \
             -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
             -DBUILD_SHARED_LIBS=OFF \
             -DWITH_EXAMPLES=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 /work/test_ssh.c -o test_ssh \
    -I./include -I./build/include build/src/libssh.a \
    -static -Wl,--allow-multiple-definition -lssl -lcrypto -lz -lpthread

WORKDIR /work
RUN ln -s build-cmplog/test_ssh bin-cmplog && \
    /work/bin-cmplog /work/test_ssh.c || true

# Copy fuzzing resources
COPY libssh/fuzz/dict /work/dict
COPY libssh/fuzz/in /work/in
COPY libssh/fuzz/fuzz.sh /work/fuzz.sh
COPY libssh/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
        -DBUILD_SHARED_LIBS=OFF \
        -DWITH_EXAMPLES=OFF && \
    make -j$(nproc)

RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping /work/test_ssh.c -o test_ssh \
    -I./include -I./build/include build/src/libssh.a \
    -fprofile-instr-generate -fcoverage-mapping -lssl -lcrypto -lz -lpthread

WORKDIR /work
RUN ln -s build-cov/test_ssh bin-cov && \
    /work/bin-cov /work/test_ssh.c || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg" \
        -DBUILD_SHARED_LIBS=OFF \
        -DWITH_EXAMPLES=OFF \
        -DCMAKE_INSTALL_PREFIX=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

RUN clang -g -O0 -pg -fno-omit-frame-pointer /work/test_ssh.c -o test_ssh \
    -I./include -I./build/include build/src/libssh.a \
    -pg -lssl -lcrypto -lz -lpthread && \
    mkdir -p /work/install-uftrace/bin && \
    cp test_ssh /work/install-uftrace/bin/

WORKDIR /work
RUN ln -s install-uftrace/bin/test_ssh bin-uftrace && \
    /work/bin-uftrace /work/test_ssh.c || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
