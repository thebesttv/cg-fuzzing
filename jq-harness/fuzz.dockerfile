FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool bison flex git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Clone jq from git (tag jq-1.8.1) to get harness files
# The release tarball doesn't include tests/jq_fuzz_*.c files
WORKDIR /src
RUN git clone --depth 1 --branch jq-1.8.1 https://github.com/jqlang/jq.git jq-1.8.1

WORKDIR /src/jq-1.8.1

# Initialize submodules (for oniguruma)
RUN git submodule init && git submodule update

# Run autoreconf to generate configure script
RUN autoreconf -fi

# Build jq library with afl-clang-lto for fuzzing (main target)
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static

RUN make -j$(nproc)

# Build the jq_fuzz_compile harness (tests jq_compile function)
RUN afl-clang-lto -O2 -c tests/jq_fuzz_compile.c \
    -I./src -o ./jq_fuzz_compile.o

# Link harness with jq library and AFL++ fuzzer runtime
# Use -fsanitize=fuzzer to get the main function from libFuzzer
RUN afl-clang-lto++ -O2 \
    -fsanitize=fuzzer \
    -static -Wl,--allow-multiple-definition \
    ./jq_fuzz_compile.o \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a \
    -o /out/jq_fuzz_compile

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf jq-1.8.1 && \
    git clone --depth 1 --branch jq-1.8.1 https://github.com/jqlang/jq.git jq-1.8.1

WORKDIR /src/jq-1.8.1

RUN git submodule init && git submodule update
RUN autoreconf -fi

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build the CMPLOG version of harness
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -c tests/jq_fuzz_compile.c \
    -I./src -o ./jq_fuzz_compile.o

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto++ -O2 \
    -fsanitize=fuzzer \
    -static -Wl,--allow-multiple-definition \
    ./jq_fuzz_compile.o \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a \
    -o /out/jq_fuzz_compile.cmplog

# Copy fuzzing resources
COPY jq-harness/fuzz/dict /out/dict
COPY jq-harness/fuzz/in /out/in
COPY jq-harness/fuzz/fuzz.sh /out/fuzz.sh
COPY jq-harness/fuzz/whatsup.sh /out/whatsup.sh

RUN chmod +x /out/fuzz.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/jq_fuzz_compile /out/jq_fuzz_compile.cmplog && \
    file /out/jq_fuzz_compile

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing jq harness'"]
