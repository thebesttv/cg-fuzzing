FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract ssdeep 2.14.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 "https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz" && \
    tar -xzf ssdeep-2.14.1.tar.gz && \
    rm ssdeep-2.14.1.tar.gz

WORKDIR /src/ssdeep-2.14.1

# Configure and build ssdeep with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make CC=afl-clang-lto CXX=afl-clang-lto++ LDFLAGS="-all-static -Wl,--allow-multiple-definition" -j$(nproc)

# Install the ssdeep binary
RUN cp ssdeep /out/ssdeep

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf ssdeep-2.14.1 && \
    wget --tries=3 --retry-connrefused --waitretry=5 "https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz" && \
    tar -xzf ssdeep-2.14.1.tar.gz && \
    rm ssdeep-2.14.1.tar.gz

WORKDIR /src/ssdeep-2.14.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto CXX=afl-clang-lto++ LDFLAGS="-all-static -Wl,--allow-multiple-definition" -j$(nproc)

# Install CMPLOG binary
RUN cp ssdeep /out/ssdeep.cmplog

# Copy fuzzing resources
COPY ssdeep/fuzz/dict /out/dict
COPY ssdeep/fuzz/in /out/in
COPY ssdeep/fuzz/fuzz.sh /out/fuzz.sh
COPY ssdeep/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/ssdeep /out/ssdeep.cmplog && \
    file /out/ssdeep && \
    /out/ssdeep -V

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing ssdeep'"]
