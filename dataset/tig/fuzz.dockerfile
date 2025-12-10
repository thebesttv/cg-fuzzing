FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool libncurses-dev libreadline-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract tig v2.6.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/jonas/tig/releases/download/tig-2.6.0/tig-2.6.0.tar.gz && \
    tar -xzf tig-2.6.0.tar.gz && \
    rm tig-2.6.0.tar.gz

WORKDIR /src/tig-2.6.0

# Build tig with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the tig binary
RUN cp src/tig /out/tig

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf tig-2.6.0 && \
    wget https://github.com/jonas/tig/releases/download/tig-2.6.0/tig-2.6.0.tar.gz && \
    tar -xzf tig-2.6.0.tar.gz && \
    rm tig-2.6.0.tar.gz

WORKDIR /src/tig-2.6.0

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/tig /out/tig.cmplog

# Copy fuzzing resources
COPY dataset/tig/fuzz/dict /out/dict
COPY dataset/tig/fuzz/in /out/in
COPY dataset/tig/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/tig/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/tig /out/tig.cmplog && \
    file /out/tig && \
    /out/tig --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tig'"]
