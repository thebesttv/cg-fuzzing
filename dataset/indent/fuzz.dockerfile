FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget texinfo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract GNU indent 2.2.13 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://ftp.gnu.org/gnu/indent/indent-2.2.13.tar.gz && \
    tar -xzf indent-2.2.13.tar.gz && \
    rm indent-2.2.13.tar.gz

WORKDIR /src/indent-2.2.13

# Build indent with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the indent binary
RUN cp src/indent /out/indent

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf indent-2.2.13 && \
    wget https://ftp.gnu.org/gnu/indent/indent-2.2.13.tar.gz && \
    tar -xzf indent-2.2.13.tar.gz && \
    rm indent-2.2.13.tar.gz

WORKDIR /src/indent-2.2.13

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/indent /out/indent.cmplog

# Copy fuzzing resources
COPY dataset/indent/fuzz/dict /out/dict
COPY dataset/indent/fuzz/in /out/in
COPY dataset/indent/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/indent/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/indent /out/indent.cmplog && \
    file /out/indent && \
    /out/indent --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing indent'"]
