FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract diction 1.11 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/diction/diction-1.11.tar.gz && \
    tar -xzf diction-1.11.tar.gz && \
    rm diction-1.11.tar.gz

WORKDIR /src/diction-1.11

# Build diction with afl-clang-lto for fuzzing (main target binary)
# Use static linking for better reproducibility
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the diction binary
RUN cp diction /out/diction

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf diction-1.11 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/diction/diction-1.11.tar.gz && \
    tar -xzf diction-1.11.tar.gz && \
    rm diction-1.11.tar.gz

WORKDIR /src/diction-1.11

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp diction /out/diction.cmplog

# Copy fuzzing resources
COPY diction/fuzz/dict /out/dict
COPY diction/fuzz/in /out/in
COPY diction/fuzz/fuzz.sh /out/fuzz.sh
COPY diction/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/diction /out/diction.cmplog && \
    file /out/diction

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing diction'"]
