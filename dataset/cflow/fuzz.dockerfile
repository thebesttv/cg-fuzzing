FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract cflow v1.7 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/cflow/cflow-1.7.tar.gz && \
    tar -xzf cflow-1.7.tar.gz && \
    rm cflow-1.7.tar.gz

WORKDIR /src/cflow-1.7

# Build cflow with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-nls

RUN make -j$(nproc)

# Install the cflow binary
RUN cp src/cflow /out/cflow

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf cflow-1.7 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/cflow/cflow-1.7.tar.gz && \
    tar -xzf cflow-1.7.tar.gz && \
    rm cflow-1.7.tar.gz

WORKDIR /src/cflow-1.7

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-nls

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/cflow /out/cflow.cmplog

# Copy fuzzing resources
COPY cflow/fuzz/dict /out/dict
COPY cflow/fuzz/in /out/in
COPY cflow/fuzz/fuzz.sh /out/fuzz.sh
COPY cflow/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/cflow /out/cflow.cmplog && \
    file /out/cflow && \
    /out/cflow --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing cflow'"]
