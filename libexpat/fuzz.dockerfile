FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libexpat 2.7.3 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/libexpat/libexpat/releases/download/R_2_7_3/expat-2.7.3.tar.gz && \
    tar -xzf expat-2.7.3.tar.gz && \
    rm expat-2.7.3.tar.gz

WORKDIR /src/expat-2.7.3

# Build xmlwf with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Install the xmlwf binary
RUN cp xmlwf/xmlwf /out/xmlwf

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf expat-2.7.3 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/libexpat/libexpat/releases/download/R_2_7_3/expat-2.7.3.tar.gz && \
    tar -xzf expat-2.7.3.tar.gz && \
    rm expat-2.7.3.tar.gz

WORKDIR /src/expat-2.7.3

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp xmlwf/xmlwf /out/xmlwf.cmplog

# Copy fuzzing resources
COPY libexpat/fuzz/dict /out/dict
COPY libexpat/fuzz/in /out/in
COPY libexpat/fuzz/fuzz.sh /out/fuzz.sh
COPY libexpat/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/xmlwf /out/xmlwf.cmplog && \
    file /out/xmlwf && \
    /out/xmlwf --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing xmlwf'"]
