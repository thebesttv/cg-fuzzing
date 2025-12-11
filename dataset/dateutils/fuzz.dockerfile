FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils flex bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract dateutils v0.4.11 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/hroptatyr/dateutils/releases/download/v0.4.11/dateutils-0.4.11.tar.xz && \
    tar -xJf dateutils-0.4.11.tar.xz && \
    rm dateutils-0.4.11.tar.xz

WORKDIR /src/dateutils-0.4.11

# Build dateutils with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Copy main binary (dconv - date converter for fuzzing date parsing)
RUN cp src/dconv /out/dconv

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf dateutils-0.4.11 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/hroptatyr/dateutils/releases/download/v0.4.11/dateutils-0.4.11.tar.xz && \
    tar -xJf dateutils-0.4.11.tar.xz && \
    rm dateutils-0.4.11.tar.xz

WORKDIR /src/dateutils-0.4.11

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp src/dconv /out/dconv.cmplog

# Copy fuzzing resources
COPY dateutils/fuzz/dict /out/dict
COPY dateutils/fuzz/in /out/in
COPY dateutils/fuzz/fuzz.sh /out/fuzz.sh
COPY dateutils/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/dconv /out/dconv.cmplog && \
    file /out/dconv && \
    /out/dconv --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing dateutils'"]
