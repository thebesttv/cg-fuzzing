FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract gzip 1.14 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/gzip/gzip-1.14.tar.gz && \
    tar -xzf gzip-1.14.tar.gz && \
    rm gzip-1.14.tar.gz

WORKDIR /src/gzip-1.14

# Build gzip with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the gzip binary
RUN cp gzip /out/gzip

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf gzip-1.14 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/gzip/gzip-1.14.tar.gz && \
    tar -xzf gzip-1.14.tar.gz && \
    rm gzip-1.14.tar.gz

WORKDIR /src/gzip-1.14

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp gzip /out/gzip.cmplog

# Copy fuzzing resources
COPY gzip/fuzz/dict /out/dict
COPY gzip/fuzz/in /out/in
COPY gzip/fuzz/fuzz.sh /out/fuzz.sh
COPY gzip/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/gzip /out/gzip.cmplog && \
    file /out/gzip && \
    /out/gzip --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing gzip'"]
