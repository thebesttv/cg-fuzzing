FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget m4 bison help2man && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract flex v2.6.4 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz && \
    tar -xzf flex-2.6.4.tar.gz && \
    rm flex-2.6.4.tar.gz

WORKDIR /src/flex-2.6.4

# Build flex with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the flex binary
RUN cp src/flex /out/flex

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf flex-2.6.4 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz && \
    tar -xzf flex-2.6.4.tar.gz && \
    rm flex-2.6.4.tar.gz

WORKDIR /src/flex-2.6.4

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/flex /out/flex.cmplog

# Copy fuzzing resources
COPY flex/fuzz/dict /out/dict
COPY flex/fuzz/in /out/in
COPY flex/fuzz/fuzz.sh /out/fuzz.sh
COPY flex/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/flex /out/flex.cmplog && \
    file /out/flex && \
    /out/flex --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing flex'"]
