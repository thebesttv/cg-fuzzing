FROM aflplusplus/aflplusplus:latest

RUN apt-get update && apt-get install -y wget && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /out

WORKDIR /src
RUN wget https://github.com/skeeto/pdjson/archive/refs/heads/master.tar.gz -O pdjson.tar.gz && \
    tar -xzf pdjson.tar.gz && rm pdjson.tar.gz

WORKDIR /src/pdjson-master
RUN afl-clang-lto -c -O2 -std=c99 pdjson.c -o pdjson.o && \
    afl-clang-lto -c -O2 -std=c99 tests/pretty.c -o tests/pretty.o && \
    afl-clang-lto -O2 -static -Wl,--allow-multiple-definition -o pretty tests/pretty.o pdjson.o
RUN cp pretty /out/pretty

WORKDIR /src
RUN rm -rf pdjson-master && \
    wget https://github.com/skeeto/pdjson/archive/refs/heads/master.tar.gz -O pdjson.tar.gz && \
    tar -xzf pdjson.tar.gz && rm pdjson.tar.gz

WORKDIR /src/pdjson-master
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 -std=c99 pdjson.c -o pdjson.o && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 -std=c99 tests/pretty.c -o tests/pretty.o && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -static -Wl,--allow-multiple-definition -o pretty tests/pretty.o pdjson.o
RUN cp pretty /out/pretty.cmplog

COPY dataset/pdjson/fuzz/dict /out/dict
COPY dataset/pdjson/fuzz/in /out/in
COPY dataset/pdjson/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/pdjson/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out
RUN ls -la /out/pretty /out/pretty.cmplog && file /out/pretty
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing pdjson'"]
