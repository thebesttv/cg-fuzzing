FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract nawk 20240728 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/onetrueawk/awk/archive/refs/tags/20240728.tar.gz -O nawk.tar.gz && \
    tar -xzf nawk.tar.gz && \
    rm nawk.tar.gz

WORKDIR /src/awk-20240728

# Build with afl-clang-lto
RUN make CC=afl-clang-lto HOSTCC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

RUN cp a.out /out/nawk

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf awk-20240728 && \
    wget https://github.com/onetrueawk/awk/archive/refs/tags/20240728.tar.gz -O nawk.tar.gz && \
    tar -xzf nawk.tar.gz && \
    rm nawk.tar.gz

WORKDIR /src/awk-20240728

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto HOSTCC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

RUN cp a.out /out/nawk.cmplog

# Copy fuzzing resources
COPY nawk/fuzz/dict /out/dict
COPY nawk/fuzz/in /out/in
COPY nawk/fuzz/fuzz.sh /out/fuzz.sh
COPY nawk/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/nawk /out/nawk.cmplog && \
    file /out/nawk && \
    /out/nawk --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing nawk'"]
