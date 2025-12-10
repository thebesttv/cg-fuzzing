FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget m4 flex && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract bison v3.8.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.gz && \
    tar -xzf bison-3.8.2.tar.gz && \
    rm bison-3.8.2.tar.gz

WORKDIR /src/bison-3.8.2

# Build bison with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the bison binary
RUN cp src/bison /out/bison

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf bison-3.8.2 && \
    wget https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.gz && \
    tar -xzf bison-3.8.2.tar.gz && \
    rm bison-3.8.2.tar.gz

WORKDIR /src/bison-3.8.2

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/bison /out/bison.cmplog

# Copy fuzzing resources
COPY bison/fuzz/dict /out/dict
COPY bison/fuzz/in /out/in
COPY bison/fuzz/fuzz.sh /out/fuzz.sh
COPY bison/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/bison /out/bison.cmplog && \
    file /out/bison && \
    /out/bison --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing bison'"]
