FROM aflplusplus/aflplusplus:latest

RUN apt-get update && apt-get install -y htop vim tmux parallel wget uftrace && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /work

RUN echo "project: schedtool" > /work/proj && \
    echo "version: 1.3.0" >> /work/proj && \
    echo "source: https://github.com/freequaos/schedtool/archive/refs/tags/schedtool-1.3.0.tar.gz" >> /work/proj

RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/freequaos/schedtool/archive/refs/tags/schedtool-1.3.0.tar.gz && \
    tar -xzf schedtool-1.3.0.tar.gz && rm schedtool-1.3.0.tar.gz && \
    cp -a schedtool-schedtool-1.3.0 build-fuzz && cp -a schedtool-schedtool-1.3.0 build-cmplog && \
    cp -a schedtool-schedtool-1.3.0 build-cov && cp -a schedtool-schedtool-1.3.0 build-uftrace && rm -rf schedtool-schedtool-1.3.0

WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/schedtool bin-fuzz && /work/bin-fuzz -v 2>&1 | head -1

WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/schedtool bin-cmplog && /work/bin-cmplog -v 2>&1 | head -1

COPY schedtool/fuzz/dict /work/dict
COPY schedtool/fuzz/in /work/in
COPY schedtool/fuzz/fuzz.sh /work/fuzz.sh
COPY schedtool/fuzz/whatsup.sh /work/whatsup.sh

WORKDIR /work/build-cov
RUN make CC=clang CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/schedtool bin-cov && /work/bin-cov -v 2>&1 | head -1 && rm -f *.profraw

WORKDIR /work/build-uftrace
RUN make CC=clang CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" LDFLAGS="-pg -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/schedtool bin-uftrace && /work/bin-uftrace -v 2>&1 | head -1 && rm -f gmon.out

WORKDIR /work
CMD ["/bin/bash"]
