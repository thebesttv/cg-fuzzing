FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download xdelta from GitHub (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/jmacd/xdelta/archive/refs/tags/v3.1.0.tar.gz && \
    tar -xzf v3.1.0.tar.gz && \
    rm v3.1.0.tar.gz

WORKDIR /src/xdelta-3.1.0/xdelta3

# Generate configure script
RUN autoreconf -fi

# Build xdelta3 with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the binary
RUN cp xdelta3 /out/xdelta3

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf xdelta-3.1.0 && \
    wget https://github.com/jmacd/xdelta/archive/refs/tags/v3.1.0.tar.gz && \
    tar -xzf v3.1.0.tar.gz && \
    rm v3.1.0.tar.gz

WORKDIR /src/xdelta-3.1.0/xdelta3

RUN autoreconf -fi

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp xdelta3 /out/xdelta3.cmplog

# Copy fuzzing resources
COPY xdelta/fuzz/dict /out/dict
COPY xdelta/fuzz/in /out/in
COPY xdelta/fuzz/fuzz.sh /out/fuzz.sh
COPY xdelta/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/xdelta3 /out/xdelta3.cmplog && \
    file /out/xdelta3

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing xdelta3'"]
