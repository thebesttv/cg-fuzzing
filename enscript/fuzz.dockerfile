FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract GNU enscript 1.6.6 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/enscript/enscript-1.6.6.tar.gz && \
    tar -xzf enscript-1.6.6.tar.gz && \
    rm enscript-1.6.6.tar.gz

WORKDIR /src/enscript-1.6.6

# Build enscript with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the enscript binary
RUN cp src/enscript /out/enscript

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf enscript-1.6.6 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/enscript/enscript-1.6.6.tar.gz && \
    tar -xzf enscript-1.6.6.tar.gz && \
    rm enscript-1.6.6.tar.gz

WORKDIR /src/enscript-1.6.6

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/enscript /out/enscript.cmplog

# Copy fuzzing resources
COPY enscript/fuzz/dict /out/dict
COPY enscript/fuzz/in /out/in
COPY enscript/fuzz/fuzz.sh /out/fuzz.sh
COPY enscript/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/enscript /out/enscript.cmplog && \
    file /out/enscript && \
    /out/enscript --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing enscript'"]
