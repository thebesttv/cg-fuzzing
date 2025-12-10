FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool libbz2-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download bsdiff from GitHub (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/mendsley/bsdiff/archive/refs/heads/master.tar.gz && \
    tar -xzf master.tar.gz && \
    rm master.tar.gz

WORKDIR /src/bsdiff-master

# Generate configure script
RUN ./autogen.sh

# Build bsdiff with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -DBSDIFF_EXECUTABLE -DBSPATCH_EXECUTABLE" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the binaries
RUN cp bsdiff /out/bsdiff && cp bspatch /out/bspatch

# Build CMPLOG versions for better fuzzing
WORKDIR /src
RUN rm -rf bsdiff-master && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/mendsley/bsdiff/archive/refs/heads/master.tar.gz && \
    tar -xzf master.tar.gz && \
    rm master.tar.gz

WORKDIR /src/bsdiff-master

RUN ./autogen.sh

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -DBSDIFF_EXECUTABLE -DBSPATCH_EXECUTABLE" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binaries
RUN cp bsdiff /out/bsdiff.cmplog && cp bspatch /out/bspatch.cmplog

# Copy fuzzing resources
COPY bsdiff/fuzz/dict /out/dict
COPY bsdiff/fuzz/in /out/in
COPY bsdiff/fuzz/fuzz.sh /out/fuzz.sh
COPY bsdiff/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/bsdiff /out/bsdiff.cmplog /out/bspatch /out/bspatch.cmplog && \
    file /out/bsdiff && \
    file /out/bspatch

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing bsdiff/bspatch'"]
