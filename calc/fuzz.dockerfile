FROM aflplusplus/aflplusplus:latest

RUN apt-get update && \
    apt-get install -y wget libreadline-dev libncurses-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /out

WORKDIR /src
RUN wget https://github.com/lcn2/calc/releases/download/v2.15.1.1/calc-2.15.1.1.tar.bz2 && \
    tar -xjf calc-2.15.1.1.tar.bz2 && rm calc-2.15.1.1.tar.bz2

WORKDIR /src/calc-2.15.1.1

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    make calc-static-only -j$(nproc)

RUN cp calc-static /out/calc

WORKDIR /src
RUN rm -rf calc-2.15.1.1 && \
    wget https://github.com/lcn2/calc/releases/download/v2.15.1.1/calc-2.15.1.1.tar.bz2 && \
    tar -xjf calc-2.15.1.1.tar.bz2 && rm calc-2.15.1.1.tar.bz2

WORKDIR /src/calc-2.15.1.1

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make calc-static-only -j$(nproc)

RUN cp calc-static /out/calc.cmplog

COPY calc/fuzz/dict /out/dict
COPY calc/fuzz/in /out/in
COPY calc/fuzz/fuzz.sh /out/fuzz.sh
COPY calc/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

RUN ls -la /out/calc /out/calc.cmplog && file /out/calc

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing calc'"]
