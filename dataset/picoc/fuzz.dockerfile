FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract picoc (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/jpoirier/picoc/archive/refs/tags/v3.2.2.tar.gz && \
    tar -xzf v3.2.2.tar.gz && \
    rm v3.2.2.tar.gz

WORKDIR /src/picoc-3.2.2

# Build picoc with afl-clang-lto for fuzzing (main target binary)
# Disable USE_READLINE for simpler static linking
RUN sed -i 's/#define USE_READLINE/\/\/ #define USE_READLINE/' platform.h && \
    make CC=afl-clang-lto \
    CFLAGS="-Wall -O2 -std=gnu11 -pedantic -DUNIX_HOST" \
    LIBS="-lm -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Copy the picoc binary
RUN cp picoc /out/picoc

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf picoc-3.2.2 && \
    wget https://github.com/jpoirier/picoc/archive/refs/tags/v3.2.2.tar.gz && \
    tar -xzf v3.2.2.tar.gz && \
    rm v3.2.2.tar.gz

WORKDIR /src/picoc-3.2.2

RUN sed -i 's/#define USE_READLINE/\/\/ #define USE_READLINE/' platform.h && \
    AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-Wall -O2 -std=gnu11 -pedantic -DUNIX_HOST" \
    LIBS="-lm -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Copy CMPLOG binary
RUN cp picoc /out/picoc.cmplog

# Copy fuzzing resources
COPY dataset/picoc/fuzz/dict /out/dict
COPY dataset/picoc/fuzz/in /out/in
COPY dataset/picoc/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/picoc/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/picoc /out/picoc.cmplog && \
    file /out/picoc

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing picoc'"]
