FROM aflplusplus/aflplusplus:latest

RUN apt-get update && apt-get install -y wget autoconf automake && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /out

WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/bmc/daemonize/archive/refs/tags/release-1.7.8.tar.gz && tar -xzf release-1.7.8.tar.gz && rm release-1.7.8.tar.gz

WORKDIR /src/daemonize-release-1.7.8
RUN CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" ./configure
RUN make -j$(nproc)
RUN cp daemonize /out/daemonize

WORKDIR /src
RUN rm -rf daemonize-release-1.7.8 && wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/bmc/daemonize/archive/refs/tags/release-1.7.8.tar.gz && tar -xzf release-1.7.8.tar.gz && rm release-1.7.8.tar.gz

WORKDIR /src/daemonize-release-1.7.8
RUN CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" AFL_LLVM_CMPLOG=1 ./configure
RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp daemonize /out/daemonize.cmplog

COPY daemonize/fuzz/dict /out/dict
COPY daemonize/fuzz/in /out/in
COPY daemonize/fuzz/fuzz.sh /out/fuzz.sh
COPY daemonize/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out
RUN ls -la /out/daemonize /out/daemonize.cmplog && file /out/daemonize

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing daemonize'"]
