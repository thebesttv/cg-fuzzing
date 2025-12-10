FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract grep 3.12 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/grep/grep-3.12.tar.gz && \
    tar -xzf grep-3.12.tar.gz && \
    rm grep-3.12.tar.gz

WORKDIR /src/grep-3.12

# Build grep with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the grep binary
RUN cp src/grep /out/grep

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf grep-3.12 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/grep/grep-3.12.tar.gz && \
    tar -xzf grep-3.12.tar.gz && \
    rm grep-3.12.tar.gz

WORKDIR /src/grep-3.12

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/grep /out/grep.cmplog

# Copy fuzzing resources
COPY grep/fuzz/dict /out/dict
COPY grep/fuzz/in /out/in
COPY grep/fuzz/fuzz.sh /out/fuzz.sh
COPY grep/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/grep /out/grep.cmplog && \
    file /out/grep && \
    /out/grep --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing grep'"]
