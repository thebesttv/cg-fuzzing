FROM aflplusplus/aflplusplus:latest

RUN apt-get update && apt-get install -y wget && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /out

WORKDIR /src
RUN wget https://invisible-island.net/datafiles/release/diffstat.tar.gz && tar -xzf diffstat.tar.gz && rm diffstat.tar.gz

WORKDIR /src/diffstat-1.68
RUN CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" ./configure
RUN make -j$(nproc)
RUN cp diffstat /out/diffstat

WORKDIR /src
RUN rm -rf diffstat-1.68 && wget https://invisible-island.net/datafiles/release/diffstat.tar.gz && tar -xzf diffstat.tar.gz && rm diffstat.tar.gz

WORKDIR /src/diffstat-1.68
RUN CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" AFL_LLVM_CMPLOG=1 ./configure
RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp diffstat /out/diffstat.cmplog

COPY dataset/diffstat/fuzz/dict /out/dict
COPY dataset/diffstat/fuzz/in /out/in
COPY dataset/diffstat/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/diffstat/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out
RUN ls -la /out/diffstat /out/diffstat.cmplog && file /out/diffstat

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing diffstat'"]
