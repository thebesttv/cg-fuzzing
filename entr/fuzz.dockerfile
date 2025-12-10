FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract entr 5.6 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/eradman/entr/archive/refs/tags/5.6.tar.gz && \
    tar -xzf 5.6.tar.gz && \
    rm 5.6.tar.gz

WORKDIR /src/entr-5.6

# Configure and build entr with afl-clang-lto for fuzzing
RUN ./configure

RUN make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)
RUN cp entr /out/entr

# Build CMPLOG version
WORKDIR /src
RUN rm -rf entr-5.6 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/eradman/entr/archive/refs/tags/5.6.tar.gz && \
    tar -xzf 5.6.tar.gz && \
    rm 5.6.tar.gz

WORKDIR /src/entr-5.6

RUN ./configure

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)
RUN cp entr /out/entr.cmplog

# Copy fuzzing resources
COPY entr/fuzz/dict /out/dict
COPY entr/fuzz/in /out/in
COPY entr/fuzz/fuzz.sh /out/fuzz.sh
COPY entr/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/entr /out/entr.cmplog && \
    file /out/entr

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing entr'"]
