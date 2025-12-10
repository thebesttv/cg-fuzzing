FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget texinfo xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract gengetopt 2.23 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/gengetopt/gengetopt-2.23.tar.xz && \
    tar -xJf gengetopt-2.23.tar.xz && \
    rm gengetopt-2.23.tar.xz

WORKDIR /src/gengetopt-2.23

# Build gengetopt with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the gengetopt binary
RUN cp src/gengetopt /out/gengetopt

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf gengetopt-2.23 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/gengetopt/gengetopt-2.23.tar.xz && \
    tar -xJf gengetopt-2.23.tar.xz && \
    rm gengetopt-2.23.tar.xz

WORKDIR /src/gengetopt-2.23

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/gengetopt /out/gengetopt.cmplog

# Copy fuzzing resources
COPY gengetopt/fuzz/dict /out/dict
COPY gengetopt/fuzz/in /out/in
COPY gengetopt/fuzz/fuzz.sh /out/fuzz.sh
COPY gengetopt/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/gengetopt /out/gengetopt.cmplog && \
    file /out/gengetopt && \
    /out/gengetopt --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing gengetopt'"]
