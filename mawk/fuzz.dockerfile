FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract mawk 1.3.4-20240905 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://invisible-mirror.net/archives/mawk/mawk-1.3.4-20240905.tgz && \
    tar -xzf mawk-1.3.4-20240905.tgz && \
    rm mawk-1.3.4-20240905.tgz

WORKDIR /src/mawk-1.3.4-20240905

# Configure and build mawk with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)
RUN cp mawk /out/mawk

# Build CMPLOG version
WORKDIR /src
RUN rm -rf mawk-1.3.4-20240905 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://invisible-mirror.net/archives/mawk/mawk-1.3.4-20240905.tgz && \
    tar -xzf mawk-1.3.4-20240905.tgz && \
    rm mawk-1.3.4-20240905.tgz

WORKDIR /src/mawk-1.3.4-20240905

RUN AFL_LLVM_CMPLOG=1 CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp mawk /out/mawk.cmplog

# Copy fuzzing resources
COPY mawk/fuzz/dict /out/dict
COPY mawk/fuzz/in /out/in
COPY mawk/fuzz/fuzz.sh /out/fuzz.sh
COPY mawk/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/mawk /out/mawk.cmplog && \
    file /out/mawk && \
    /out/mawk -W version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing mawk'"]
