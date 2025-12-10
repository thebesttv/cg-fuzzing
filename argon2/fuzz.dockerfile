FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract argon2 20190702 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/P-H-C/phc-winner-argon2/archive/refs/tags/20190702.tar.gz && \
    tar -xzf 20190702.tar.gz && \
    rm 20190702.tar.gz

WORKDIR /src/phc-winner-argon2-20190702

# Build argon2 with afl-clang-lto for fuzzing (main target binary)
# Only build the CLI binary (argon2), not shared library
RUN make CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -pthread -Iinclude -Isrc" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -pthread" \
    argon2 \
    -j$(nproc)

# Install the argon2 binary
RUN cp argon2 /out/argon2

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf phc-winner-argon2-20190702 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/P-H-C/phc-winner-argon2/archive/refs/tags/20190702.tar.gz && \
    tar -xzf 20190702.tar.gz && \
    rm 20190702.tar.gz

WORKDIR /src/phc-winner-argon2-20190702

RUN make CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -pthread -Iinclude -Isrc" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -pthread" \
    AFL_LLVM_CMPLOG=1 \
    argon2 \
    -j$(nproc)

# Install CMPLOG binary
RUN cp argon2 /out/argon2.cmplog

# Copy fuzzing resources
COPY argon2/fuzz/dict /out/dict
COPY argon2/fuzz/in /out/in
COPY argon2/fuzz/fuzz.sh /out/fuzz.sh
COPY argon2/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/argon2 /out/argon2.cmplog && \
    file /out/argon2 && \
    echo "test" | /out/argon2 password -t 1 -m 10 -p 1 -l 16 -e || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing argon2'"]
