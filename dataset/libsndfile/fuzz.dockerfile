FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils autogen libtool pkg-config python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libsndfile 1.2.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/libsndfile/libsndfile/releases/download/1.2.2/libsndfile-1.2.2.tar.xz && \
    tar -xJf libsndfile-1.2.2.tar.xz && \
    rm libsndfile-1.2.2.tar.xz

WORKDIR /src/libsndfile-1.2.2

# Build libsndfile with afl-clang-lto for fuzzing (main target binary)
# Use static linking and disable external libs
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static \
    --disable-external-libs --disable-mpeg

RUN make -j$(nproc)

# Install the sndfile-info binary
RUN cp programs/sndfile-info /out/sndfile-info

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libsndfile-1.2.2 && \
    wget https://github.com/libsndfile/libsndfile/releases/download/1.2.2/libsndfile-1.2.2.tar.xz && \
    tar -xJf libsndfile-1.2.2.tar.xz && \
    rm libsndfile-1.2.2.tar.xz

WORKDIR /src/libsndfile-1.2.2

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static \
    --disable-external-libs --disable-mpeg

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp programs/sndfile-info /out/sndfile-info.cmplog

# Copy fuzzing resources
COPY dataset/libsndfile/fuzz/dict /out/dict
COPY dataset/libsndfile/fuzz/in /out/in
COPY dataset/libsndfile/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libsndfile/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/sndfile-info /out/sndfile-info.cmplog && \
    file /out/sndfile-info

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libsndfile'"]
