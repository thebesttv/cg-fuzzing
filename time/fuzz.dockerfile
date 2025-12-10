FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract time 1.9 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/time/time-1.9.tar.gz && \
    tar -xzf time-1.9.tar.gz && \
    rm time-1.9.tar.gz

WORKDIR /src/time-1.9

# Build time with afl-clang-lto for fuzzing (main target binary)
# Use static linking
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the time binary
RUN cp time /out/time

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf time-1.9 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/time/time-1.9.tar.gz && \
    tar -xzf time-1.9.tar.gz && \
    rm time-1.9.tar.gz

WORKDIR /src/time-1.9

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp time /out/time.cmplog

# Copy fuzzing resources
COPY time/fuzz/dict /out/dict
COPY time/fuzz/in /out/in
COPY time/fuzz/fuzz.sh /out/fuzz.sh
COPY time/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/time /out/time.cmplog && \
    file /out/time && \
    /out/time --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing time'"]
