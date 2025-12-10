FROM aflplusplus/aflplusplus:latest

RUN apt-get update && \
    apt-get install -y wget autoconf automake autopoint libtool pkg-config gettext bison flex && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /out

WORKDIR /src
RUN wget https://github.com/util-linux/util-linux/archive/refs/tags/v2.40.2.tar.gz && \
    tar -xzf v2.40.2.tar.gz && \
    rm v2.40.2.tar.gz

WORKDIR /src/util-linux-2.40.2
RUN ./autogen.sh

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-all-programs --enable-libuuid

RUN make -j$(nproc)
RUN find . -name "uuidgen" -executable -type f | head -1 | xargs -I {} cp {} /out/uuidgen

WORKDIR /src
RUN rm -rf util-linux-2.40.2 && \
    wget https://github.com/util-linux/util-linux/archive/refs/tags/v2.40.2.tar.gz && \
    tar -xzf v2.40.2.tar.gz && \
    rm v2.40.2.tar.gz

WORKDIR /src/util-linux-2.40.2
RUN ./autogen.sh

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --disable-all-programs --enable-libuuid

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN find . -name "uuidgen" -executable -type f | head -1 | xargs -I {} cp {} /out/uuidgen.cmplog

COPY util-linux/fuzz/dict /out/dict
COPY util-linux/fuzz/in /out/in
COPY util-linux/fuzz/fuzz.sh /out/fuzz.sh
COPY util-linux/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

RUN ls -la /out/uuidgen /out/uuidgen.cmplog && file /out/uuidgen

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing util-linux'"]
