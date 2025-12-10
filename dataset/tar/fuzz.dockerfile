FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract tar v1.35 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://ftp.gnu.org/gnu/tar/tar-1.35.tar.xz && \
    tar -xJf tar-1.35.tar.xz && \
    rm tar-1.35.tar.xz

WORKDIR /src/tar-1.35

# Build tar with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the tar binary
RUN cp src/tar /out/tar

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf tar-1.35 && \
    wget https://ftp.gnu.org/gnu/tar/tar-1.35.tar.xz && \
    tar -xJf tar-1.35.tar.xz && \
    rm tar-1.35.tar.xz

WORKDIR /src/tar-1.35

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/tar /out/tar.cmplog

# Copy fuzzing resources
COPY dataset/tar/fuzz/dict /out/dict
COPY dataset/tar/fuzz/in /out/in
COPY dataset/tar/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/tar/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/tar /out/tar.cmplog && \
    file /out/tar && \
    /out/tar --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tar'"]
