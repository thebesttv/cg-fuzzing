FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: bearssl" > /work/proj && \
    echo "version: 0.6" >> /work/proj && \
    echo "source: https://bearssl.org/bearssl-0.6.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://bearssl.org/bearssl-0.6.tar.gz && \
    tar -xzf bearssl-0.6.tar.gz && \
    rm bearssl-0.6.tar.gz && \
    cp -a bearssl-0.6 build-fuzz && \
    cp -a bearssl-0.6 build-cmplog && \
    cp -a bearssl-0.6 build-cov && \
    cp -a bearssl-0.6 build-uftrace && \
    rm -rf bearssl-0.6

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto CFLAGS="-O2 -fPIC" lib -j$(nproc) && \
    for f in tools/*.c; do \
        obj=build/obj/$(basename ${f%.c}).o; \
        afl-clang-lto -O2 -fPIC -Isrc -Iinc -c -o $obj $f; \
    done && \
    afl-clang-lto -static -Wl,--allow-multiple-definition -o build/brssl \
        build/obj/brssl.o build/obj/certs.o build/obj/chain.o build/obj/client.o \
        build/obj/errors.o build/obj/files.o build/obj/impl.o build/obj/keys.o \
        build/obj/names.o build/obj/server.o build/obj/skey.o build/obj/sslio.o \
        build/obj/ta.o build/obj/twrch.o build/obj/vector.o build/obj/verify.o \
        build/obj/xmem.o build/libbearssl.a

WORKDIR /work
RUN ln -s build-fuzz/build/brssl bin-fuzz && \
    echo "BearSSL brssl binary created"

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto CFLAGS="-O2 -fPIC" lib -j$(nproc) && \
    for f in tools/*.c; do \
        obj=build/obj/$(basename ${f%.c}).o; \
        AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -fPIC -Isrc -Iinc -c -o $obj $f; \
    done && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -static -Wl,--allow-multiple-definition -o build/brssl \
        build/obj/brssl.o build/obj/certs.o build/obj/chain.o build/obj/client.o \
        build/obj/errors.o build/obj/files.o build/obj/impl.o build/obj/keys.o \
        build/obj/names.o build/obj/server.o build/obj/skey.o build/obj/sslio.o \
        build/obj/ta.o build/obj/twrch.o build/obj/vector.o build/obj/verify.o \
        build/obj/xmem.o build/libbearssl.a

WORKDIR /work
RUN ln -s build-cmplog/build/brssl bin-cmplog && \
    echo "BearSSL brssl cmplog binary created"

# Copy fuzzing resources
COPY bearssl/fuzz/dict /work/dict
COPY bearssl/fuzz/in /work/in
COPY bearssl/fuzz/fuzz.sh /work/fuzz.sh
COPY bearssl/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -fPIC" lib -j$(nproc) && \
    for f in tools/*.c; do \
        obj=build/obj/$(basename ${f%.c}).o; \
        clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -fPIC -Isrc -Iinc -c -o $obj $f; \
    done && \
    clang -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition -o build/brssl \
        build/obj/brssl.o build/obj/certs.o build/obj/chain.o build/obj/client.o \
        build/obj/errors.o build/obj/files.o build/obj/impl.o build/obj/keys.o \
        build/obj/names.o build/obj/server.o build/obj/skey.o build/obj/sslio.o \
        build/obj/ta.o build/obj/twrch.o build/obj/vector.o build/obj/verify.o \
        build/obj/xmem.o build/libbearssl.a

WORKDIR /work
RUN ln -s build-cov/build/brssl bin-cov && \
    echo "BearSSL brssl cov binary created" && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang CFLAGS="-g -O0 -pg -fno-omit-frame-pointer -fPIC" lib -j$(nproc) && \
    for f in tools/*.c; do \
        obj=build/obj/$(basename ${f%.c}).o; \
        clang -g -O0 -pg -fno-omit-frame-pointer -fPIC -Isrc -Iinc -c -o $obj $f; \
    done && \
    clang -pg -Wl,--allow-multiple-definition -o build/brssl \
        build/obj/brssl.o build/obj/certs.o build/obj/chain.o build/obj/client.o \
        build/obj/errors.o build/obj/files.o build/obj/impl.o build/obj/keys.o \
        build/obj/names.o build/obj/server.o build/obj/skey.o build/obj/sslio.o \
        build/obj/ta.o build/obj/twrch.o build/obj/vector.o build/obj/verify.o \
        build/obj/xmem.o build/libbearssl.a

WORKDIR /work
RUN ln -s build-uftrace/build/brssl bin-uftrace && \
    echo "BearSSL brssl uftrace binary created" && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
