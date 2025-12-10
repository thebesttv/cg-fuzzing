FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract hoedown (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/hoedown/hoedown/archive/refs/tags/3.0.7.tar.gz -O hoedown-3.0.7.tar.gz && \
    tar -xzf hoedown-3.0.7.tar.gz && \
    rm hoedown-3.0.7.tar.gz

WORKDIR /src/hoedown-3.0.7

# Build with afl-clang-lto
RUN CC=afl-clang-lto \
    CFLAGS="-O2 -ansi -pedantic -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make hoedown

RUN cp hoedown /out/hoedown

# Build CMPLOG version
WORKDIR /src
RUN rm -rf hoedown-3.0.7 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/hoedown/hoedown/archive/refs/tags/3.0.7.tar.gz -O hoedown-3.0.7.tar.gz && \
    tar -xzf hoedown-3.0.7.tar.gz && \
    rm hoedown-3.0.7.tar.gz

WORKDIR /src/hoedown-3.0.7

RUN CC=afl-clang-lto \
    CFLAGS="-O2 -ansi -pedantic -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make hoedown

RUN cp hoedown /out/hoedown.cmplog

# Copy fuzzing resources
COPY hoedown/fuzz/dict /out/dict
COPY hoedown/fuzz/in /out/in
COPY hoedown/fuzz/fuzz.sh /out/fuzz.sh
COPY hoedown/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/hoedown /out/hoedown.cmplog && \
    file /out/hoedown && \
    echo "# Test" | /out/hoedown

# Default command
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing hoedown'"]
