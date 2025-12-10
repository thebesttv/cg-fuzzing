FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libreadline-dev curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract mujs 1.3.8 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/ArtifexSoftware/mujs/archive/refs/tags/1.3.8.tar.gz && \
    tar -xzf 1.3.8.tar.gz && \
    rm 1.3.8.tar.gz

WORKDIR /src/mujs-1.3.8

# Build mujs with afl-clang-lto for fuzzing (main target binary)
# Use static linking - mujs Makefile doesn't use LDFLAGS for linking
# So we need to add static flags to CFLAGS as well
# First build libmujs.o, then link manually
RUN make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    build/release/libmujs.o

# Link statically
RUN afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
    -o build/release/mujs main.c build/release/libmujs.o -lm

# Install the mujs binary
RUN cp build/release/mujs /out/mujs

# Build CMPLOG version for better fuzzing (comparison logging)
# Save Unicode data files before cleaning (they are downloaded from unicode.org during build)
# and can fail due to network issues
WORKDIR /src/mujs-1.3.8
RUN cp /src/mujs-1.3.8/UnicodeData.txt /src/mujs-1.3.8/SpecialCasing.txt /tmp/ || true

# Clean and rebuild for CMPLOG
WORKDIR /src
RUN rm -rf mujs-1.3.8 && \
    wget https://github.com/ArtifexSoftware/mujs/archive/refs/tags/1.3.8.tar.gz && \
    tar -xzf 1.3.8.tar.gz && \
    rm 1.3.8.tar.gz

WORKDIR /src/mujs-1.3.8

# Restore Unicode data files to avoid re-downloading (network can be flaky), then clean up temp files
RUN (cp /tmp/UnicodeData.txt /tmp/SpecialCasing.txt . && rm -f /tmp/UnicodeData.txt /tmp/SpecialCasing.txt) || true

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    build/release/libmujs.o

# Link statically with CMPLOG
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
    -o build/release/mujs main.c build/release/libmujs.o -lm

# Install CMPLOG binary
RUN cp build/release/mujs /out/mujs.cmplog

# Copy fuzzing resources
COPY dataset/mujs/fuzz/dict /out/dict
COPY dataset/mujs/fuzz/in /out/in
COPY dataset/mujs/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/mujs/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/mujs /out/mujs.cmplog && \
    file /out/mujs

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing mujs'"]
