FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libpng 1.6.47 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.sourceforge.net/libpng/libpng-1.6.47.tar.gz && \
    tar -xzf libpng-1.6.47.tar.gz && \
    rm libpng-1.6.47.tar.gz

WORKDIR /src/libpng-1.6.47

# Build with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Build png2pnm (the CLI tool for fuzzing)
WORKDIR /src/libpng-1.6.47/contrib/pngminus
RUN afl-clang-lto -O2 -I../.. -L../../.libs png2pnm.c -o png2pnm -lpng16 -lz -lm \
    -static -Wl,--allow-multiple-definition

# Install the binary
RUN cp png2pnm /out/png2pnm

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libpng-1.6.47 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.sourceforge.net/libpng/libpng-1.6.47.tar.gz && \
    tar -xzf libpng-1.6.47.tar.gz && \
    rm libpng-1.6.47.tar.gz

WORKDIR /src/libpng-1.6.47

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build CMPLOG version of png2pnm
WORKDIR /src/libpng-1.6.47/contrib/pngminus
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I../.. -L../../.libs png2pnm.c -o png2pnm.cmplog \
    -lpng16 -lz -lm -static -Wl,--allow-multiple-definition

# Install CMPLOG binary
RUN cp png2pnm.cmplog /out/png2pnm.cmplog

# Copy fuzzing resources
COPY libpng/fuzz/dict /out/dict
COPY libpng/fuzz/in /out/in
COPY libpng/fuzz/fuzz.sh /out/fuzz.sh
COPY libpng/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/png2pnm /out/png2pnm.cmplog && \
    file /out/png2pnm

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libpng (png2pnm)'"]
