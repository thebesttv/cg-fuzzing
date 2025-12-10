FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract cpio 2.15 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/cpio/cpio-2.15.tar.gz && \
    tar -xzf cpio-2.15.tar.gz && \
    rm cpio-2.15.tar.gz

WORKDIR /src/cpio-2.15

# Build cpio with afl-clang-lto for fuzzing (main target binary)
# Use static linking
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the cpio binary
RUN cp src/cpio /out/cpio

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf cpio-2.15 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/cpio/cpio-2.15.tar.gz && \
    tar -xzf cpio-2.15.tar.gz && \
    rm cpio-2.15.tar.gz

WORKDIR /src/cpio-2.15

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/cpio /out/cpio.cmplog

# Copy fuzzing resources
COPY cpio/fuzz/dict /out/dict
COPY cpio/fuzz/in /out/in
COPY cpio/fuzz/fuzz.sh /out/fuzz.sh
COPY cpio/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/cpio /out/cpio.cmplog && \
    file /out/cpio && \
    /out/cpio --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing cpio'"]
