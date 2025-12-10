FROM aflplusplus/aflplusplus:latest

RUN apt-get update && \
    apt-get install -y wget cmake libssl-dev zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /out

WORKDIR /src
RUN wget https://github.com/libssh2/libssh2/releases/download/libssh2-1.11.1/libssh2-1.11.1.tar.gz && \
    tar -xzf libssh2-1.11.1.tar.gz && \
    rm libssh2-1.11.1.tar.gz

WORKDIR /src/libssh2-1.11.1

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_EXAMPLES=ON \
        -DBUILD_TESTING=OFF

WORKDIR /src/libssh2-1.11.1/build
RUN make -j$(nproc)
RUN cp example/ssh2 /out/ssh2 || cp example/direct_tcpip /out/ssh2 || echo "Finding example binary..." && cp $(find example -type f -executable | head -1) /out/ssh2

WORKDIR /src
RUN rm -rf libssh2-1.11.1 && \
    wget https://github.com/libssh2/libssh2/releases/download/libssh2-1.11.1/libssh2-1.11.1.tar.gz && \
    tar -xzf libssh2-1.11.1.tar.gz && \
    rm libssh2-1.11.1.tar.gz

WORKDIR /src/libssh2-1.11.1

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_EXAMPLES=ON \
        -DBUILD_TESTING=OFF

WORKDIR /src/libssh2-1.11.1/build
RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp example/ssh2 /out/ssh2.cmplog || cp example/direct_tcpip /out/ssh2.cmplog || cp $(find example -type f -executable | head -1) /out/ssh2.cmplog

COPY libssh2/fuzz/dict /out/dict
COPY libssh2/fuzz/in /out/in
COPY libssh2/fuzz/fuzz.sh /out/fuzz.sh
COPY libssh2/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

RUN ls -la /out/ssh2 /out/ssh2.cmplog && file /out/ssh2

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libssh2'"]
