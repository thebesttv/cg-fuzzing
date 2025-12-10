FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget bzip2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract mpg123 v1.32.7 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://downloads.sourceforge.net/project/mpg123/mpg123/1.32.7/mpg123-1.32.7.tar.bz2 && \
    tar -xjf mpg123-1.32.7.tar.bz2 && \
    rm mpg123-1.32.7.tar.bz2

WORKDIR /src/mpg123-1.32.7

# Build mpg123 with afl-clang-lto for fuzzing (main target binary)
# Use static linking and disable audio output
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static --with-audio=dummy

RUN make -j$(nproc)

# Copy the mpg123 binary
RUN cp src/mpg123 /out/mpg123

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf mpg123-1.32.7 && \
    wget https://downloads.sourceforge.net/project/mpg123/mpg123/1.32.7/mpg123-1.32.7.tar.bz2 && \
    tar -xjf mpg123-1.32.7.tar.bz2 && \
    rm mpg123-1.32.7.tar.bz2

WORKDIR /src/mpg123-1.32.7

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static --with-audio=dummy

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp src/mpg123 /out/mpg123.cmplog

# Copy fuzzing resources
COPY mpg123/fuzz/dict /out/dict
COPY mpg123/fuzz/in /out/in
COPY mpg123/fuzz/fuzz.sh /out/fuzz.sh
COPY mpg123/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/mpg123 /out/mpg123.cmplog && \
    file /out/mpg123 && \
    /out/mpg123 --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing mpg123'"]
