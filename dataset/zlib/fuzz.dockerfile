FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract zlib 1.3.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz && \
    tar -xzf zlib-1.3.1.tar.gz && \
    rm zlib-1.3.1.tar.gz

WORKDIR /src/zlib-1.3.1

# Build with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --static

RUN make -j$(nproc)
RUN make -j$(nproc) minigzip

# Install the minigzip binary
RUN cp minigzip /out/minigzip

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf zlib-1.3.1 && \
    wget https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz && \
    tar -xzf zlib-1.3.1.tar.gz && \
    rm zlib-1.3.1.tar.gz

WORKDIR /src/zlib-1.3.1

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN AFL_LLVM_CMPLOG=1 make -j$(nproc) minigzip

# Install CMPLOG binary
RUN cp minigzip /out/minigzip.cmplog

# Copy fuzzing resources
COPY dataset/zlib/fuzz/dict /out/dict
COPY dataset/zlib/fuzz/in /out/in
COPY dataset/zlib/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/zlib/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/minigzip /out/minigzip.cmplog && \
    file /out/minigzip

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing zlib (minigzip)'"]
