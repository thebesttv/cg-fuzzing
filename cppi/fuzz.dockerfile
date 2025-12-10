FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract cppi v1.18 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 --no-check-certificate https://mirror.keystealth.org/gnu/cppi/cppi-1.18.tar.xz && \
    tar -xf cppi-1.18.tar.xz && \
    rm cppi-1.18.tar.xz

WORKDIR /src/cppi-1.18

# Build cppi with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure

RUN make -j$(nproc)

# Install the cppi binary
RUN cp src/cppi /out/cppi

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf cppi-1.18 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 --no-check-certificate https://mirror.keystealth.org/gnu/cppi/cppi-1.18.tar.xz && \
    tar -xf cppi-1.18.tar.xz && \
    rm cppi-1.18.tar.xz

WORKDIR /src/cppi-1.18

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/cppi /out/cppi.cmplog

# Copy fuzzing resources
COPY cppi/fuzz/dict /out/dict
COPY cppi/fuzz/in /out/in
COPY cppi/fuzz/fuzz.sh /out/fuzz.sh
COPY cppi/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/cppi /out/cppi.cmplog && \
    file /out/cppi && \
    /out/cppi --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing cppi'"]
