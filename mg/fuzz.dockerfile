FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev libncurses5-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract mg v3.7 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/troglobit/mg/releases/download/v3.7/mg-3.7.tar.gz && \
    tar -xzf mg-3.7.tar.gz && \
    rm mg-3.7.tar.gz

WORKDIR /src/mg-3.7

# Build mg with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --prefix=/usr

RUN make -j$(nproc)

# Install the mg binary
RUN cp src/mg /out/mg

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf mg-3.7 && \
    wget https://github.com/troglobit/mg/releases/download/v3.7/mg-3.7.tar.gz && \
    tar -xzf mg-3.7.tar.gz && \
    rm mg-3.7.tar.gz

WORKDIR /src/mg-3.7

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --prefix=/usr

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/mg /out/mg.cmplog

# Copy fuzzing resources
COPY mg/fuzz/dict /out/dict
COPY mg/fuzz/in /out/in
COPY mg/fuzz/fuzz.sh /out/fuzz.sh
COPY mg/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/mg /out/mg.cmplog && \
    file /out/mg

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing mg'"]
