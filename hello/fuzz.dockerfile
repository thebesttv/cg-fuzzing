FROM aflplusplus/aflplusplus:latest

RUN apt-get update && apt-get install -y wget && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /out

WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz && \
    tar -xzf hello-2.12.1.tar.gz && rm hello-2.12.1.tar.gz

WORKDIR /src/hello-2.12.1

RUN CC=afl-clang-lto CXX=afl-clang-lto++ CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" ./configure --disable-shared

RUN make -j$(nproc)
RUN cp hello /out/hello

WORKDIR /src
RUN rm -rf hello-2.12.1 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz && \
    tar -xzf hello-2.12.1.tar.gz && rm hello-2.12.1.tar.gz

WORKDIR /src/hello-2.12.1

RUN CC=afl-clang-lto CXX=afl-clang-lto++ CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" AFL_LLVM_CMPLOG=1 ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp hello /out/hello.cmplog

COPY hello/fuzz/dict /out/dict
COPY hello/fuzz/in /out/in
COPY hello/fuzz/fuzz.sh /out/fuzz.sh
COPY hello/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

RUN ls -la /out/hello /out/hello.cmplog && file /out/hello && /out/hello --version

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing hello'"]
