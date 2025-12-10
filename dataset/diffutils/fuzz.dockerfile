FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract diffutils 3.12 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://ftpmirror.gnu.org/gnu/diffutils/diffutils-3.12.tar.gz && \
    tar -xzf diffutils-3.12.tar.gz && \
    rm diffutils-3.12.tar.gz

WORKDIR /src/diffutils-3.12

# Build diff with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the diff binary
RUN cp src/diff /out/diff

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf diffutils-3.12 && \
    wget https://ftpmirror.gnu.org/gnu/diffutils/diffutils-3.12.tar.gz && \
    tar -xzf diffutils-3.12.tar.gz && \
    rm diffutils-3.12.tar.gz

WORKDIR /src/diffutils-3.12

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/diff /out/diff.cmplog

# Copy fuzzing resources
COPY diffutils/fuzz/dict /out/dict
COPY diffutils/fuzz/in /out/in
COPY diffutils/fuzz/fuzz.sh /out/fuzz.sh
COPY diffutils/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/diff /out/diff.cmplog && \
    file /out/diff && \
    /out/diff --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing diff'"]
