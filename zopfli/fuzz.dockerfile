FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract zopfli v1.0.3 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/google/zopfli/archive/refs/tags/zopfli-1.0.3.tar.gz && \
    tar -xzf zopfli-1.0.3.tar.gz && \
    rm zopfli-1.0.3.tar.gz

WORKDIR /src/zopfli-zopfli-1.0.3

# Build zopfli with afl-clang-lto
RUN make CC=afl-clang-lto \
    CFLAGS="-O2 -W -Wall -Wextra -ansi -pedantic -lm -Wno-unused-function" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    zopfli

# Install the zopfli binary
RUN cp zopfli /out/zopfli

# Build CMPLOG version
WORKDIR /src
RUN rm -rf zopfli-zopfli-1.0.3 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/google/zopfli/archive/refs/tags/zopfli-1.0.3.tar.gz && \
    tar -xzf zopfli-1.0.3.tar.gz && \
    rm zopfli-1.0.3.tar.gz

WORKDIR /src/zopfli-zopfli-1.0.3

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2 -W -Wall -Wextra -ansi -pedantic -lm -Wno-unused-function" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    zopfli

# Install CMPLOG binary
RUN cp zopfli /out/zopfli.cmplog

# Copy fuzzing resources
COPY zopfli/fuzz/dict /out/dict
COPY zopfli/fuzz/in /out/in
COPY zopfli/fuzz/fuzz.sh /out/fuzz.sh
COPY zopfli/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/zopfli /out/zopfli.cmplog && \
    file /out/zopfli && \
    /out/zopfli -h || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing zopfli'"]
