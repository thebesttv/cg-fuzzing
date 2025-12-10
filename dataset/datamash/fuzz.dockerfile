FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract datamash 1.9 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://ftp.gnu.org/gnu/datamash/datamash-1.9.tar.gz && \
    tar -xzf datamash-1.9.tar.gz && \
    rm datamash-1.9.tar.gz

WORKDIR /src/datamash-1.9

# Build datamash with afl-clang-lto for fuzzing (main target binary)
# Use static linking for better reproducibility
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the datamash binary
RUN cp datamash /out/datamash

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf datamash-1.9 && \
    wget https://ftp.gnu.org/gnu/datamash/datamash-1.9.tar.gz && \
    tar -xzf datamash-1.9.tar.gz && \
    rm datamash-1.9.tar.gz

WORKDIR /src/datamash-1.9

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp datamash /out/datamash.cmplog

# Copy fuzzing resources
COPY dataset/datamash/fuzz/dict /out/dict
COPY dataset/datamash/fuzz/in /out/in
COPY dataset/datamash/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/datamash/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/datamash /out/datamash.cmplog && \
    file /out/datamash && \
    /out/datamash --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing datamash'"]
