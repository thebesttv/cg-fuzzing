FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget bison flex && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract cproto 4.7w (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://invisible-mirror.net/archives/cproto/cproto-4.7w.tgz && \
    tar -xzf cproto-4.7w.tgz && \
    rm cproto-4.7w.tgz

WORKDIR /src/cproto-4.7w

# Build cproto with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the cproto binary
RUN cp cproto /out/cproto

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf cproto-4.7w && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://invisible-mirror.net/archives/cproto/cproto-4.7w.tgz && \
    tar -xzf cproto-4.7w.tgz && \
    rm cproto-4.7w.tgz

WORKDIR /src/cproto-4.7w

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp cproto /out/cproto.cmplog

# Copy fuzzing resources
COPY cproto/fuzz/dict /out/dict
COPY cproto/fuzz/in /out/in
COPY cproto/fuzz/fuzz.sh /out/fuzz.sh
COPY cproto/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/cproto /out/cproto.cmplog && \
    file /out/cproto && \
    /out/cproto -V || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing cproto'"]
