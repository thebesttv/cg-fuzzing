FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract utf8proc v2.11.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v2.11.2.tar.gz && \
    tar -xzf v2.11.2.tar.gz && \
    rm v2.11.2.tar.gz

WORKDIR /src/utf8proc-2.11.2

# Build utf8proc library with afl-clang-lto
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make libutf8proc.a

# Build the fuzzer binary with afl-clang-lto
RUN afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o utf8proc_fuzz \
    test/fuzz_main.c test/fuzzer.c libutf8proc.a

RUN cp utf8proc_fuzz /out/utf8proc_fuzz

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf utf8proc-2.11.2 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v2.11.2.tar.gz && \
    tar -xzf v2.11.2.tar.gz && \
    rm v2.11.2.tar.gz

WORKDIR /src/utf8proc-2.11.2

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make libutf8proc.a

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o utf8proc_fuzz \
    test/fuzz_main.c test/fuzzer.c libutf8proc.a

RUN cp utf8proc_fuzz /out/utf8proc_fuzz.cmplog

# Copy fuzzing resources
COPY utf8proc/fuzz/dict /out/dict
COPY utf8proc/fuzz/in /out/in
COPY utf8proc/fuzz/fuzz.sh /out/fuzz.sh
COPY utf8proc/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/utf8proc_fuzz /out/utf8proc_fuzz.cmplog && \
    file /out/utf8proc_fuzz

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing utf8proc'"]
