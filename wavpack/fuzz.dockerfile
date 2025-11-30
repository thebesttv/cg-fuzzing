FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract WavPack 5.8.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/dbry/WavPack/releases/download/5.8.1/wavpack-5.8.1.tar.xz && \
    tar -xf wavpack-5.8.1.tar.xz && \
    rm wavpack-5.8.1.tar.xz

WORKDIR /src/wavpack-5.8.1

# Build wvunpack with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Install the main fuzzing binary (wvunpack - decodes .wv files)
RUN cp cli/wvunpack /out/wvunpack

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf wavpack-5.8.1 && \
    wget https://github.com/dbry/WavPack/releases/download/5.8.1/wavpack-5.8.1.tar.xz && \
    tar -xf wavpack-5.8.1.tar.xz && \
    rm wavpack-5.8.1.tar.xz

WORKDIR /src/wavpack-5.8.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp cli/wvunpack /out/wvunpack.cmplog

# Copy fuzzing resources
COPY wavpack/fuzz/dict /out/dict
COPY wavpack/fuzz/in /out/in
COPY wavpack/fuzz/fuzz.sh /out/fuzz.sh
COPY wavpack/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/wvunpack /out/wvunpack.cmplog && \
    file /out/wvunpack

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing wvunpack'"]
