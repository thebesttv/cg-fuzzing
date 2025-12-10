FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download re2c 4.3 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/skvadrik/re2c/releases/download/4.3/re2c-4.3.tar.xz && \
    tar -xf re2c-4.3.tar.xz && \
    rm re2c-4.3.tar.xz

WORKDIR /src/re2c-4.3

# Build re2c with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the binary
RUN cp re2c /out/re2c

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf re2c-4.3 && \
    wget https://github.com/skvadrik/re2c/releases/download/4.3/re2c-4.3.tar.xz && \
    tar -xf re2c-4.3.tar.xz && \
    rm re2c-4.3.tar.xz

WORKDIR /src/re2c-4.3

RUN CC=afl-clang-lto CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp re2c /out/re2c.cmplog

# Copy fuzzing resources
COPY dataset/0-re2c/fuzz/dict /out/dict
COPY dataset/0-re2c/fuzz/in /out/in
COPY dataset/0-re2c/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/0-re2c/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/re2c /out/re2c.cmplog && \
    file /out/re2c && \
    /out/re2c --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing re2c'"]
