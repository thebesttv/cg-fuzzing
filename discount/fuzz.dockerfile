FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract discount v3.0.1.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/Orc/discount/archive/refs/tags/v3.0.1.2.tar.gz && \
    tar -xzf v3.0.1.2.tar.gz && \
    rm v3.0.1.2.tar.gz

WORKDIR /src/discount-3.0.1.2

# Build discount with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure.sh

RUN make -j$(nproc)

# Install the markdown binary
RUN cp markdown /out/markdown

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf discount-3.0.1.2 && \
    wget https://github.com/Orc/discount/archive/refs/tags/v3.0.1.2.tar.gz && \
    tar -xzf v3.0.1.2.tar.gz && \
    rm v3.0.1.2.tar.gz

WORKDIR /src/discount-3.0.1.2

RUN CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure.sh

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp markdown /out/markdown.cmplog

# Copy fuzzing resources
COPY discount/fuzz/dict /out/dict
COPY discount/fuzz/in /out/in
COPY discount/fuzz/fuzz.sh /out/fuzz.sh
COPY discount/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/markdown /out/markdown.cmplog && \
    file /out/markdown

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing discount'"]
