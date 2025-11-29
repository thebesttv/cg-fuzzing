FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libyaml 0.2.5 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz && \
    tar -xzf yaml-0.2.5.tar.gz && \
    rm yaml-0.2.5.tar.gz

WORKDIR /src/yaml-0.2.5

# Build with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Install the run-parser binary
RUN cp tests/run-parser /out/run-parser

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf yaml-0.2.5 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz && \
    tar -xzf yaml-0.2.5.tar.gz && \
    rm yaml-0.2.5.tar.gz

WORKDIR /src/yaml-0.2.5

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp tests/run-parser /out/run-parser.cmplog

# Copy fuzzing resources
COPY libyaml/fuzz/dict /out/dict
COPY libyaml/fuzz/in /out/in
COPY libyaml/fuzz/fuzz.sh /out/fuzz.sh
COPY libyaml/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/run-parser /out/run-parser.cmplog && \
    file /out/run-parser

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing run-parser'"]
