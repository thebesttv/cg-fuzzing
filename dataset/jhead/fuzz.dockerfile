FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract jhead 3.08 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/Matthias-Wandel/jhead/archive/refs/tags/3.08.tar.gz && \
    tar -xzf 3.08.tar.gz && \
    rm 3.08.tar.gz

WORKDIR /src/jhead-3.08

# Build jhead with afl-clang-lto for fuzzing (main target binary)
# Use static linking
RUN make clean 2>/dev/null || true && \
    make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Install the jhead binary
RUN cp jhead /out/jhead

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf jhead-3.08 && \
    wget https://github.com/Matthias-Wandel/jhead/archive/refs/tags/3.08.tar.gz && \
    tar -xzf 3.08.tar.gz && \
    rm 3.08.tar.gz

WORKDIR /src/jhead-3.08

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Install CMPLOG binary
RUN cp jhead /out/jhead.cmplog

# Copy fuzzing resources
COPY dataset/jhead/fuzz/dict /out/dict
COPY dataset/jhead/fuzz/in /out/in
COPY dataset/jhead/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/jhead/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/jhead /out/jhead.cmplog && \
    file /out/jhead && \
    /out/jhead -V

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing jhead'"]
