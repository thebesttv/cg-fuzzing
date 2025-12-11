FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract tinyexpr (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/codeplea/tinyexpr/archive/refs/heads/master.tar.gz -O tinyexpr.tar.gz && \
    tar -xzf tinyexpr.tar.gz && \
    rm tinyexpr.tar.gz

WORKDIR /src/tinyexpr-master

# Build tinyexpr repl with afl-clang-lto for fuzzing
RUN afl-clang-lto -c -O2 -Wall tinyexpr.c -o tinyexpr.o && \
    afl-clang-lto -c -O2 -Wall repl.c -o repl.o && \
    afl-clang-lto -O2 -static -Wl,--allow-multiple-definition -o repl repl.o tinyexpr.o -lm

RUN cp repl /out/repl

# Build CMPLOG version
WORKDIR /src
RUN rm -rf tinyexpr-master && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/codeplea/tinyexpr/archive/refs/heads/master.tar.gz -O tinyexpr.tar.gz && \
    tar -xzf tinyexpr.tar.gz && \
    rm tinyexpr.tar.gz

WORKDIR /src/tinyexpr-master

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 -Wall tinyexpr.c -o tinyexpr.o && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 -Wall repl.c -o repl.o && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -static -Wl,--allow-multiple-definition -o repl repl.o tinyexpr.o -lm

RUN cp repl /out/repl.cmplog

# Copy fuzzing resources
COPY tinyexpr/fuzz/dict /out/dict
COPY tinyexpr/fuzz/in /out/in
COPY tinyexpr/fuzz/fuzz.sh /out/fuzz.sh
COPY tinyexpr/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/repl /out/repl.cmplog && \
    file /out/repl

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tinyexpr repl'"]
