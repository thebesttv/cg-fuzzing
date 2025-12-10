FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract cabextract v1.11 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://www.cabextract.org.uk/cabextract-1.11.tar.gz && \
    tar -xzf cabextract-1.11.tar.gz && \
    rm cabextract-1.11.tar.gz

WORKDIR /src/cabextract-1.11

# Build cabextract with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the cabextract binary
RUN cp cabextract /out/cabextract

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf cabextract-1.11 && \
    wget https://www.cabextract.org.uk/cabextract-1.11.tar.gz && \
    tar -xzf cabextract-1.11.tar.gz && \
    rm cabextract-1.11.tar.gz

WORKDIR /src/cabextract-1.11

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp cabextract /out/cabextract.cmplog

# Copy fuzzing resources
COPY cabextract/fuzz/dict /out/dict
COPY cabextract/fuzz/in /out/in
COPY cabextract/fuzz/fuzz.sh /out/fuzz.sh
COPY cabextract/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/cabextract /out/cabextract.cmplog && \
    file /out/cabextract && \
    /out/cabextract --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing cabextract'"]
