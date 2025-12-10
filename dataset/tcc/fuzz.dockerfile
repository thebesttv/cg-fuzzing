FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract TCC v0.9.27 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27.tar.bz2 && \
    tar -xjf tcc-0.9.27.tar.bz2 && \
    rm tcc-0.9.27.tar.bz2

WORKDIR /src/tcc-0.9.27

# Build TCC with afl-clang-lto for fuzzing
# Disable bcheck as it fails on newer glibc
RUN ./configure --prefix=/usr/local --disable-bcheck \
    --cc=afl-clang-lto \
    --extra-cflags="-O2" \
    --extra-ldflags="-static -Wl,--allow-multiple-definition"

RUN make tcc -j$(nproc)
RUN cp tcc /out/tcc

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf tcc-0.9.27 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27.tar.bz2 && \
    tar -xjf tcc-0.9.27.tar.bz2 && \
    rm tcc-0.9.27.tar.bz2

WORKDIR /src/tcc-0.9.27

RUN AFL_LLVM_CMPLOG=1 ./configure --prefix=/usr/local --disable-bcheck \
    --cc=afl-clang-lto \
    --extra-cflags="-O2" \
    --extra-ldflags="-static -Wl,--allow-multiple-definition"

RUN AFL_LLVM_CMPLOG=1 make tcc -j$(nproc)
RUN cp tcc /out/tcc.cmplog

# Copy fuzzing resources
COPY tcc/fuzz/dict /out/dict
COPY tcc/fuzz/in /out/in
COPY tcc/fuzz/fuzz.sh /out/fuzz.sh
COPY tcc/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/tcc /out/tcc.cmplog && \
    file /out/tcc && \
    /out/tcc -v

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tcc'"]
