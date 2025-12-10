FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libssl-dev zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract httrack v3.49.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://mirror.httrack.com/httrack-3.49.2.tar.gz && \
    tar -xzf httrack-3.49.2.tar.gz && \
    rm httrack-3.49.2.tar.gz

WORKDIR /src/httrack-3.49.2

# Build httrack with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the httrack binary
RUN cp src/httrack /out/httrack

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf httrack-3.49.2 && \
    wget https://mirror.httrack.com/httrack-3.49.2.tar.gz && \
    tar -xzf httrack-3.49.2.tar.gz && \
    rm httrack-3.49.2.tar.gz

WORKDIR /src/httrack-3.49.2

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/httrack /out/httrack.cmplog

# Copy fuzzing resources
COPY dataset/httrack/fuzz/dict /out/dict
COPY dataset/httrack/fuzz/in /out/in
COPY dataset/httrack/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/httrack/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/httrack /out/httrack.cmplog && \
    file /out/httrack

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing httrack'"]
