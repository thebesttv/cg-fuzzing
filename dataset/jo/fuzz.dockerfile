FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract jo 1.9 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jpmens/jo/releases/download/1.9/jo-1.9.tar.gz && \
    tar -xzf jo-1.9.tar.gz && \
    rm jo-1.9.tar.gz

WORKDIR /src/jo-1.9

# Build jo with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)
RUN cp jo /out/jo

# Build CMPLOG version
WORKDIR /src
RUN rm -rf jo-1.9 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jpmens/jo/releases/download/1.9/jo-1.9.tar.gz && \
    tar -xzf jo-1.9.tar.gz && \
    rm jo-1.9.tar.gz

WORKDIR /src/jo-1.9

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp jo /out/jo.cmplog

# Copy fuzzing resources
COPY jo/fuzz/dict /out/dict
COPY jo/fuzz/in /out/in
COPY jo/fuzz/fuzz.sh /out/fuzz.sh
COPY jo/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/jo /out/jo.cmplog && \
    file /out/jo && \
    /out/jo -v

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing jo'"]
