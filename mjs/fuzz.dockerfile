FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract mjs (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/cesanta/mjs/archive/refs/tags/2.20.0.tar.gz && \
    tar -xzf 2.20.0.tar.gz && \
    rm 2.20.0.tar.gz

WORKDIR /src/mjs-2.20.0

# Build mjs with afl-clang-lto for fuzzing (main target binary)
RUN mkdir -p build && \
    afl-clang-lto -DMJS_MAIN -I. -Isrc \
    -O2 \
    mjs.c -lm \
    -static -Wl,--allow-multiple-definition \
    -o build/mjs

# Copy the mjs binary
RUN cp build/mjs /out/mjs

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf mjs-2.20.0 && \
    wget https://github.com/cesanta/mjs/archive/refs/tags/2.20.0.tar.gz && \
    tar -xzf 2.20.0.tar.gz && \
    rm 2.20.0.tar.gz

WORKDIR /src/mjs-2.20.0

RUN mkdir -p build && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -DMJS_MAIN -I. -Isrc \
    -O2 \
    mjs.c -lm \
    -static -Wl,--allow-multiple-definition \
    -o build/mjs

# Copy CMPLOG binary
RUN cp build/mjs /out/mjs.cmplog

# Copy fuzzing resources
COPY mjs/fuzz/dict /out/dict
COPY mjs/fuzz/in /out/in
COPY mjs/fuzz/fuzz.sh /out/fuzz.sh
COPY mjs/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/mjs /out/mjs.cmplog && \
    file /out/mjs && \
    /out/mjs -e 'print(1+1)'

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing mjs'"]
