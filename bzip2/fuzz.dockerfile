FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract bzip2 1.0.8 from official GitLab repository (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://gitlab.com/bzip2/bzip2/-/archive/bzip2-1.0.8/bzip2-bzip2-1.0.8.tar.gz && \
    tar -xzf bzip2-bzip2-1.0.8.tar.gz && \
    rm bzip2-bzip2-1.0.8.tar.gz

WORKDIR /src/bzip2-bzip2-1.0.8

# Build with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN make clean || true && \
    make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2 -Wall -Winline -D_FILE_OFFSET_BITS=64" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    bzip2

# Install the bzip2 binary
RUN cp bzip2 /out/bzip2

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf bzip2-bzip2-1.0.8 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://gitlab.com/bzip2/bzip2/-/archive/bzip2-1.0.8/bzip2-bzip2-1.0.8.tar.gz && \
    tar -xzf bzip2-bzip2-1.0.8.tar.gz && \
    rm bzip2-bzip2-1.0.8.tar.gz

WORKDIR /src/bzip2-bzip2-1.0.8

RUN make clean || true && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2 -Wall -Winline -D_FILE_OFFSET_BITS=64" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    bzip2

# Install CMPLOG binary
RUN cp bzip2 /out/bzip2.cmplog

# Copy fuzzing resources
COPY bzip2/fuzz/dict /out/dict
COPY bzip2/fuzz/in /out/in
COPY bzip2/fuzz/fuzz.sh /out/fuzz.sh
COPY bzip2/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/bzip2 /out/bzip2.cmplog && \
    file /out/bzip2 && \
    /out/bzip2 --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing bzip2'"]
