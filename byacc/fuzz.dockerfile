FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract byacc 20240109 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://invisible-mirror.net/archives/byacc/byacc-20240109.tgz && \
    tar -xzf byacc-20240109.tgz && \
    rm byacc-20240109.tgz

WORKDIR /src/byacc-20240109

# Build byacc with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the yacc binary
RUN cp yacc /out/yacc

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf byacc-20240109 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://invisible-mirror.net/archives/byacc/byacc-20240109.tgz && \
    tar -xzf byacc-20240109.tgz && \
    rm byacc-20240109.tgz

WORKDIR /src/byacc-20240109

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp yacc /out/yacc.cmplog

# Copy fuzzing resources
COPY byacc/fuzz/dict /out/dict
COPY byacc/fuzz/in /out/in
COPY byacc/fuzz/fuzz.sh /out/fuzz.sh
COPY byacc/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/yacc /out/yacc.cmplog && \
    file /out/yacc && \
    /out/yacc -V

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing byacc'"]
