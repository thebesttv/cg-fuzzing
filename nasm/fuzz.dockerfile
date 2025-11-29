FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract nasm v2.16.03 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://www.nasm.us/pub/nasm/releasebuilds/2.16.03/nasm-2.16.03.tar.gz && \
    tar -xzf nasm-2.16.03.tar.gz && \
    rm nasm-2.16.03.tar.gz

WORKDIR /src/nasm-2.16.03

# Build nasm with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the nasm binary
RUN cp nasm /out/nasm

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf nasm-2.16.03 && \
    wget https://www.nasm.us/pub/nasm/releasebuilds/2.16.03/nasm-2.16.03.tar.gz && \
    tar -xzf nasm-2.16.03.tar.gz && \
    rm nasm-2.16.03.tar.gz

WORKDIR /src/nasm-2.16.03

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp nasm /out/nasm.cmplog

# Copy fuzzing resources
COPY nasm/fuzz/dict /out/dict
COPY nasm/fuzz/in /out/in
COPY nasm/fuzz/fuzz.sh /out/fuzz.sh
COPY nasm/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/nasm /out/nasm.cmplog && \
    file /out/nasm && \
    /out/nasm --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing nasm'"]
