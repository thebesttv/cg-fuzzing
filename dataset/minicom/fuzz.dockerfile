FROM aflplusplus/aflplusplus:latest

RUN apt-get update && \
    apt-get install -y wget autoconf automake gettext libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /out

WORKDIR /src
RUN wget https://salsa.debian.org/minicom-team/minicom/-/archive/2.9/minicom-2.9.tar.gz && \
    tar -xzf minicom-2.9.tar.gz && \
    rm minicom-2.9.tar.gz

WORKDIR /src/minicom-2.9
RUN ./autogen.sh

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN make -j$(nproc)
RUN cp src/minicom /out/minicom

WORKDIR /src
RUN rm -rf minicom-2.9 && \
    wget https://salsa.debian.org/minicom-team/minicom/-/archive/2.9/minicom-2.9.tar.gz && \
    tar -xzf minicom-2.9.tar.gz && \
    rm minicom-2.9.tar.gz

WORKDIR /src/minicom-2.9
RUN ./autogen.sh

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp src/minicom /out/minicom.cmplog

COPY dataset/minicom/fuzz/dict /out/dict
COPY dataset/minicom/fuzz/in /out/in
COPY dataset/minicom/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/minicom/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

RUN ls -la /out/minicom /out/minicom.cmplog && \
    file /out/minicom

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing minicom'"]
