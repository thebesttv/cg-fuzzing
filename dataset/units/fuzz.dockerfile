FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract GNU units 2.24 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/units/units-2.24.tar.gz && \
    tar -xzf units-2.24.tar.gz && \
    rm units-2.24.tar.gz

WORKDIR /src/units-2.24

# Build units with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the units binary and data file
RUN cp units /out/units && \
    cp definitions.units /out/definitions.units

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf units-2.24 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/units/units-2.24.tar.gz && \
    tar -xzf units-2.24.tar.gz && \
    rm units-2.24.tar.gz

WORKDIR /src/units-2.24

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp units /out/units.cmplog

# Copy fuzzing resources
COPY units/fuzz/dict /out/dict
COPY units/fuzz/in /out/in
COPY units/fuzz/fuzz.sh /out/fuzz.sh
COPY units/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/units /out/units.cmplog && \
    file /out/units && \
    /out/units --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing units'"]
