FROM aflplusplus/aflplusplus:latest

RUN apt-get update && apt-get install -y wget && apt-get clean

RUN mkdir -p /out

WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://downloads.sourceforge.net/lame/lame-3.100.tar.gz && \
    tar -xzf lame-3.100.tar.gz && rm lame-3.100.tar.gz

WORKDIR /src/lame-3.100

RUN CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static
RUN make -j$(nproc)
RUN cp frontend/lame /out/lame

WORKDIR /src
RUN rm -rf lame-3.100 && wget --tries=3 --retry-connrefused --waitretry=5 https://downloads.sourceforge.net/lame/lame-3.100.tar.gz && \
    tar -xzf lame-3.100.tar.gz && rm lame-3.100.tar.gz

WORKDIR /src/lame-3.100
RUN CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 ./configure --disable-shared --enable-static
RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp frontend/lame /out/lame.cmplog

COPY lame/fuzz/dict /out/dict
COPY lame/fuzz/in /out/in
COPY lame/fuzz/fuzz.sh /out/fuzz.sh
COPY lame/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out
RUN ls -la /out/lame /out/lame.cmplog && file /out/lame

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing lame'"]
