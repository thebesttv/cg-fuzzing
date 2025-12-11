FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract hunspell v1.7.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/hunspell/hunspell/releases/download/v1.7.2/hunspell-1.7.2.tar.gz && \
    tar -xzf hunspell-1.7.2.tar.gz && \
    rm hunspell-1.7.2.tar.gz

WORKDIR /src/hunspell-1.7.2

# Build hunspell with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -static-libstdc++" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Copy the hunspell binary
RUN cp src/tools/hunspell /out/hunspell

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf hunspell-1.7.2 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/hunspell/hunspell/releases/download/v1.7.2/hunspell-1.7.2.tar.gz && \
    tar -xzf hunspell-1.7.2.tar.gz && \
    rm hunspell-1.7.2.tar.gz

WORKDIR /src/hunspell-1.7.2

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -static-libstdc++" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp src/tools/hunspell /out/hunspell.cmplog

# Copy fuzzing resources
COPY hunspell/fuzz/dict /out/dict
COPY hunspell/fuzz/in /out/in
COPY hunspell/fuzz/fuzz.sh /out/fuzz.sh
COPY hunspell/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/hunspell /out/hunspell.cmplog && \
    file /out/hunspell

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing hunspell'"]
