FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libfyaml v0.9 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/pantoniou/libfyaml/releases/download/v0.9/libfyaml-0.9.tar.gz && \
    tar -xzf libfyaml-0.9.tar.gz && \
    rm libfyaml-0.9.tar.gz

WORKDIR /src/libfyaml-0.9

# Build libfyaml with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Install the fy-tool binary
RUN cp src/fy-tool /out/fy-tool

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libfyaml-0.9 && \
    wget https://github.com/pantoniou/libfyaml/releases/download/v0.9/libfyaml-0.9.tar.gz && \
    tar -xzf libfyaml-0.9.tar.gz && \
    rm libfyaml-0.9.tar.gz

WORKDIR /src/libfyaml-0.9

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/fy-tool /out/fy-tool.cmplog

# Copy fuzzing resources
COPY dataset/libfyaml/fuzz/dict /out/dict
COPY dataset/libfyaml/fuzz/in /out/in
COPY dataset/libfyaml/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libfyaml/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/fy-tool /out/fy-tool.cmplog && \
    file /out/fy-tool && \
    /out/fy-tool --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libfyaml'"]
