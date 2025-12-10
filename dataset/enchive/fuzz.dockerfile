FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract enchive v3.5 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/skeeto/enchive/archive/refs/tags/3.5.tar.gz && \
    tar -xzf 3.5.tar.gz && \
    rm 3.5.tar.gz

WORKDIR /src/enchive-3.5

# Build with afl-clang-lto for fuzzing (main target binary)
RUN make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

RUN cp enchive /out/enchive

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf enchive-3.5 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/skeeto/enchive/archive/refs/tags/3.5.tar.gz && \
    tar -xzf 3.5.tar.gz && \
    rm 3.5.tar.gz

WORKDIR /src/enchive-3.5

RUN make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1

RUN cp enchive /out/enchive.cmplog

# Copy fuzzing resources
COPY enchive/fuzz/dict /out/dict
COPY enchive/fuzz/in /out/in
COPY enchive/fuzz/fuzz.sh /out/fuzz.sh
COPY enchive/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/enchive /out/enchive.cmplog && \
    file /out/enchive && \
    /out/enchive --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing enchive'"]
