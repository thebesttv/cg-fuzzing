FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev libzstd-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract file 5.46 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://astron.com/pub/file/file-5.46.tar.gz && \
    tar -xzf file-5.46.tar.gz && \
    rm file-5.46.tar.gz

WORKDIR /src/file-5.46

# Build file with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Install the file binary
RUN cp src/file /out/file
# Also copy the magic database
RUN cp -r magic/magic.mgc /out/magic.mgc

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf file-5.46 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://astron.com/pub/file/file-5.46.tar.gz && \
    tar -xzf file-5.46.tar.gz && \
    rm file-5.46.tar.gz

WORKDIR /src/file-5.46

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/file /out/file.cmplog

# Copy fuzzing resources
COPY file/fuzz/dict /out/dict
COPY file/fuzz/in /out/in
COPY file/fuzz/fuzz.sh /out/fuzz.sh
COPY file/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/file /out/file.cmplog && \
    file /out/file && \
    /out/file -m /out/magic.mgc /out/file

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing file'"]
