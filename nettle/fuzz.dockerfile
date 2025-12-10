FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libgmp-dev m4 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract nettle 3.10.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/nettle/nettle-3.10.2.tar.gz && \
    tar -xzf nettle-3.10.2.tar.gz && \
    rm nettle-3.10.2.tar.gz

WORKDIR /src/nettle-3.10.2

# Build nettle with afl-clang-lto for fuzzing
# Use static linking for better reproducibility
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-openssl --enable-static

RUN make -j$(nproc)

# Install the sexp-conv binary (S-expression converter, reads from stdin)
RUN cp tools/sexp-conv /out/sexp-conv

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf nettle-3.10.2 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/nettle/nettle-3.10.2.tar.gz && \
    tar -xzf nettle-3.10.2.tar.gz && \
    rm nettle-3.10.2.tar.gz

WORKDIR /src/nettle-3.10.2

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --disable-openssl --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp tools/sexp-conv /out/sexp-conv.cmplog

# Copy fuzzing resources
COPY nettle/fuzz/dict /out/dict
COPY nettle/fuzz/in /out/in
COPY nettle/fuzz/fuzz.sh /out/fuzz.sh
COPY nettle/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/sexp-conv /out/sexp-conv.cmplog && \
    file /out/sexp-conv && \
    /out/sexp-conv --help || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing nettle sexp-conv'"]
