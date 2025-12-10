FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract jsmn v1.1.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/zserge/jsmn/archive/refs/tags/v1.1.0.tar.gz && \
    tar -xzf v1.1.0.tar.gz && \
    rm v1.1.0.tar.gz

WORKDIR /src/jsmn-1.1.0

# Build jsondump with afl-clang-lto for fuzzing (main target binary)
# jsmn is header-only, so we compile jsondump.c with jsmn.h included
RUN afl-clang-lto \
    -O2 \
    -DJSMN_PARENT_LINKS \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o jsondump \
    example/jsondump.c

RUN cp jsondump /out/jsondump

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf jsmn-1.1.0 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/zserge/jsmn/archive/refs/tags/v1.1.0.tar.gz && \
    tar -xzf v1.1.0.tar.gz && \
    rm v1.1.0.tar.gz

WORKDIR /src/jsmn-1.1.0

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto \
    -O2 \
    -DJSMN_PARENT_LINKS \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o jsondump \
    example/jsondump.c

RUN cp jsondump /out/jsondump.cmplog

# Copy fuzzing resources
COPY jsmn/fuzz/dict /out/dict
COPY jsmn/fuzz/in /out/in
COPY jsmn/fuzz/fuzz.sh /out/fuzz.sh
COPY jsmn/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/jsondump /out/jsondump.cmplog && \
    file /out/jsondump

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing jsmn'"]
