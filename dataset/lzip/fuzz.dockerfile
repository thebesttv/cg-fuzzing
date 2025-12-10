FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download lzip from GNU (same version as bc.dockerfile)
WORKDIR /src
RUN wget http://download.savannah.gnu.org/releases/lzip/lzip-1.15.tar.gz && \
    tar -xzf lzip-1.15.tar.gz && \
    rm lzip-1.15.tar.gz

WORKDIR /src/lzip-1.15

# Build lzip with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make CXX=afl-clang-lto++ -j$(nproc)
RUN cp lzip /out/lzip

# Build CMPLOG version
WORKDIR /src
RUN rm -rf lzip-1.15 && \
    wget http://download.savannah.gnu.org/releases/lzip/lzip-1.15.tar.gz && \
    tar -xzf lzip-1.15.tar.gz && \
    rm lzip-1.15.tar.gz

WORKDIR /src/lzip-1.15

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make CXX=afl-clang-lto++ -j$(nproc)
RUN cp lzip /out/lzip.cmplog

# Copy fuzzing resources
COPY lzip/fuzz/dict /out/dict
COPY lzip/fuzz/in /out/in
COPY lzip/fuzz/fuzz.sh /out/fuzz.sh
COPY lzip/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/lzip /out/lzip.cmplog && \
    file /out/lzip

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing lzip'"]
