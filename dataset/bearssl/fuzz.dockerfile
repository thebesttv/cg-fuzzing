FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract BearSSL 0.6 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://bearssl.org/bearssl-0.6.tar.gz && \
    tar -xzf bearssl-0.6.tar.gz && \
    rm bearssl-0.6.tar.gz

WORKDIR /src/bearssl-0.6

# Build BearSSL with afl-clang-lto for fuzzing
# Build only the library first
RUN make CC=afl-clang-lto CFLAGS="-O2 -fPIC" lib -j$(nproc)

# Build tools separately, compiling object files with afl-clang-lto
RUN for f in tools/*.c; do \
        obj=build/obj/$(basename ${f%.c}).o; \
        afl-clang-lto -O2 -fPIC -Isrc -Iinc -c -o $obj $f; \
    done

# Link the brssl binary with afl-clang-lto
RUN afl-clang-lto -static -Wl,--allow-multiple-definition -o build/brssl \
    build/obj/brssl.o build/obj/certs.o build/obj/chain.o build/obj/client.o \
    build/obj/errors.o build/obj/files.o build/obj/impl.o build/obj/keys.o \
    build/obj/names.o build/obj/server.o build/obj/skey.o build/obj/sslio.o \
    build/obj/ta.o build/obj/twrch.o build/obj/vector.o build/obj/verify.o \
    build/obj/xmem.o build/libbearssl.a

RUN cp build/brssl /out/brssl

# Build CMPLOG version
WORKDIR /src
RUN rm -rf bearssl-0.6 && \
    wget https://bearssl.org/bearssl-0.6.tar.gz && \
    tar -xzf bearssl-0.6.tar.gz && \
    rm bearssl-0.6.tar.gz

WORKDIR /src/bearssl-0.6

# Build library with CMPLOG
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto CFLAGS="-O2 -fPIC" lib -j$(nproc)

# Build tools separately with CMPLOG
RUN for f in tools/*.c; do \
        obj=build/obj/$(basename ${f%.c}).o; \
        AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -fPIC -Isrc -Iinc -c -o $obj $f; \
    done

# Link the brssl binary with afl-clang-lto
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -static -Wl,--allow-multiple-definition -o build/brssl \
    build/obj/brssl.o build/obj/certs.o build/obj/chain.o build/obj/client.o \
    build/obj/errors.o build/obj/files.o build/obj/impl.o build/obj/keys.o \
    build/obj/names.o build/obj/server.o build/obj/skey.o build/obj/sslio.o \
    build/obj/ta.o build/obj/twrch.o build/obj/vector.o build/obj/verify.o \
    build/obj/xmem.o build/libbearssl.a

RUN cp build/brssl /out/brssl.cmplog

# Copy fuzzing resources
COPY dataset/bearssl/fuzz/dict /out/dict
COPY dataset/bearssl/fuzz/in /out/in
COPY dataset/bearssl/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/bearssl/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/brssl /out/brssl.cmplog && \
    file /out/brssl

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing brssl'"]
