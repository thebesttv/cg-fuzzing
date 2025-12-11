FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract oniguruma 6.9.10 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/kkos/oniguruma/releases/download/v6.9.10/onig-6.9.10.tar.gz && \
    tar -xzf onig-6.9.10.tar.gz && \
    rm onig-6.9.10.tar.gz

WORKDIR /src/onig-6.9.10

# Build oniguruma with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Build the sample utility manually with static linking
RUN cd sample && \
    afl-clang-lto -O2 -I../src -o simple simple.c ../src/.libs/libonig.a -static -Wl,--allow-multiple-definition

# Install the simple binary
RUN cp sample/simple /out/simple

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf onig-6.9.10 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/kkos/oniguruma/releases/download/v6.9.10/onig-6.9.10.tar.gz && \
    tar -xzf onig-6.9.10.tar.gz && \
    rm onig-6.9.10.tar.gz

WORKDIR /src/onig-6.9.10

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build the sample utility with CMPLOG
RUN cd sample && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I../src -o simple simple.c ../src/.libs/libonig.a -static -Wl,--allow-multiple-definition

# Install CMPLOG binary
RUN cp sample/simple /out/simple.cmplog

# Copy fuzzing resources
COPY oniguruma/fuzz/dict /out/dict
COPY oniguruma/fuzz/in /out/in
COPY oniguruma/fuzz/fuzz.sh /out/fuzz.sh
COPY oniguruma/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/simple /out/simple.cmplog && \
    file /out/simple

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing oniguruma simple'"]
