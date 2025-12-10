FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libidn 1.42 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/libidn/libidn-1.42.tar.gz && \
    tar -xzf libidn-1.42.tar.gz && \
    rm libidn-1.42.tar.gz

WORKDIR /src/libidn-1.42

# Configure libidn with afl-clang-lto
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)
RUN cp src/idn /out/idn

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf libidn-1.42 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/libidn/libidn-1.42.tar.gz && \
    tar -xzf libidn-1.42.tar.gz && \
    rm libidn-1.42.tar.gz

WORKDIR /src/libidn-1.42

RUN AFL_LLVM_CMPLOG=1 CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp src/idn /out/idn.cmplog

# Copy fuzzing resources
COPY libidn/fuzz/dict /out/dict
COPY libidn/fuzz/in /out/in
COPY libidn/fuzz/fuzz.sh /out/fuzz.sh
COPY libidn/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/idn /out/idn.cmplog && \
    file /out/idn && \
    /out/idn --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libidn'"]
