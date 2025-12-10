FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download duktape 2.7.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/svaarala/duktape/releases/download/v2.7.0/duktape-2.7.0.tar.xz && \
    tar -xf duktape-2.7.0.tar.xz && \
    rm duktape-2.7.0.tar.xz

WORKDIR /src/duktape-2.7.0

# Build duktape CLI with afl-clang-lto for fuzzing
RUN afl-clang-lto -O2 -std=c99 \
    -I./src \
    -o duk \
    ./src/duktape.c \
    ./examples/cmdline/duk_cmdline.c \
    -lm \
    -static -Wl,--allow-multiple-definition

# Install the binary
RUN cp duk /out/duk

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf duktape-2.7.0 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/svaarala/duktape/releases/download/v2.7.0/duktape-2.7.0.tar.xz && \
    tar -xf duktape-2.7.0.tar.xz && \
    rm duktape-2.7.0.tar.xz

WORKDIR /src/duktape-2.7.0

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -std=c99 \
    -I./src \
    -o duk.cmplog \
    ./src/duktape.c \
    ./examples/cmdline/duk_cmdline.c \
    -lm \
    -static -Wl,--allow-multiple-definition

# Install CMPLOG binary
RUN cp duk.cmplog /out/duk.cmplog

# Copy fuzzing resources
COPY duktape/fuzz/dict /out/dict
COPY duktape/fuzz/in /out/in
COPY duktape/fuzz/fuzz.sh /out/fuzz.sh
COPY duktape/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/duk /out/duk.cmplog && \
    file /out/duk

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing duktape'"]
