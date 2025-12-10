FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract recutils v1.9 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/recutils/recutils-1.9.tar.gz && \
    tar -xzf recutils-1.9.tar.gz && \
    rm recutils-1.9.tar.gz

WORKDIR /src/recutils-1.9

# Build recutils with afl-clang-lto for fuzzing (main target binary)
# Add -Wno-error=implicit-function-declaration to handle older code
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -Wno-error=implicit-function-declaration" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN make

# Install the recsel binary (good for fuzzing - reads rec files)
RUN cp utils/recsel /out/recsel

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf recutils-1.9 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/recutils/recutils-1.9.tar.gz && \
    tar -xzf recutils-1.9.tar.gz && \
    rm recutils-1.9.tar.gz

WORKDIR /src/recutils-1.9

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -Wno-error=implicit-function-declaration" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make

# Install CMPLOG binary
RUN cp utils/recsel /out/recsel.cmplog

# Copy fuzzing resources
COPY recutils/fuzz/dict /out/dict
COPY recutils/fuzz/in /out/in
COPY recutils/fuzz/fuzz.sh /out/fuzz.sh
COPY recutils/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/recsel /out/recsel.cmplog && \
    file /out/recsel && \
    /out/recsel --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing recutils'"]
