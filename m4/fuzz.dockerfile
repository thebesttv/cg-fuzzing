FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract m4 v1.4.19 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.gz && \
    tar -xzf m4-1.4.19.tar.gz && \
    rm m4-1.4.19.tar.gz

WORKDIR /src/m4-1.4.19

# Build m4 with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the m4 binary
RUN cp src/m4 /out/m4

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf m4-1.4.19 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.gz && \
    tar -xzf m4-1.4.19.tar.gz && \
    rm m4-1.4.19.tar.gz

WORKDIR /src/m4-1.4.19

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/m4 /out/m4.cmplog

# Copy fuzzing resources
COPY m4/fuzz/dict /out/dict
COPY m4/fuzz/in /out/in
COPY m4/fuzz/fuzz.sh /out/fuzz.sh
COPY m4/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/m4 /out/m4.cmplog && \
    file /out/m4 && \
    /out/m4 --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing m4'"]
