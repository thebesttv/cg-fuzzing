FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract xz v5.8.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/tukaani-project/xz/releases/download/v5.8.1/xz-5.8.1.tar.gz && \
    tar -xzf xz-5.8.1.tar.gz && \
    rm xz-5.8.1.tar.gz

WORKDIR /src/xz-5.8.1

# Build xz with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Install the xz binary
RUN cp src/xz/xz /out/xz

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf xz-5.8.1 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/tukaani-project/xz/releases/download/v5.8.1/xz-5.8.1.tar.gz && \
    tar -xzf xz-5.8.1.tar.gz && \
    rm xz-5.8.1.tar.gz

WORKDIR /src/xz-5.8.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/xz/xz /out/xz.cmplog

# Copy fuzzing resources
COPY xz/fuzz/dict /out/dict
COPY xz/fuzz/in /out/in
COPY xz/fuzz/fuzz.sh /out/fuzz.sh
COPY xz/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/xz /out/xz.cmplog && \
    file /out/xz && \
    /out/xz --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing xz'"]
