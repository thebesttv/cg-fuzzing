FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget flex bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract recode (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/rrthomas/recode/releases/download/v3.7.14/recode-3.7.14.tar.gz && \
    tar -xzf recode-3.7.14.tar.gz && \
    rm recode-3.7.14.tar.gz

WORKDIR /src/recode-3.7.14

# Build with afl-clang-lto
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --without-libiconv-prefix

RUN make -j$(nproc)
RUN cp src/recode /out/recode

# Build CMPLOG version
WORKDIR /src
RUN rm -rf recode-3.7.14 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/rrthomas/recode/releases/download/v3.7.14/recode-3.7.14.tar.gz && \
    tar -xzf recode-3.7.14.tar.gz && \
    rm recode-3.7.14.tar.gz

WORKDIR /src/recode-3.7.14

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --without-libiconv-prefix

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp src/recode /out/recode.cmplog

# Copy fuzzing resources
COPY recode/fuzz/dict /out/dict
COPY recode/fuzz/in /out/in
COPY recode/fuzz/fuzz.sh /out/fuzz.sh
COPY recode/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/recode /out/recode.cmplog && \
    file /out/recode && \
    /out/recode --version

# Default command
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing recode'"]
