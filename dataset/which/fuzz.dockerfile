FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract which 2.23 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://ftp.gnu.org/gnu/which/which-2.23.tar.gz && \
    tar -xzf which-2.23.tar.gz && \
    rm which-2.23.tar.gz

WORKDIR /src/which-2.23

# Build which with afl-clang-lto for fuzzing (main target binary)
# Use static linking
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the which binary
RUN cp which /out/which

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf which-2.23 && \
    wget https://ftp.gnu.org/gnu/which/which-2.23.tar.gz && \
    tar -xzf which-2.23.tar.gz && \
    rm which-2.23.tar.gz

WORKDIR /src/which-2.23

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp which /out/which.cmplog

# Copy fuzzing resources
COPY dataset/which/fuzz/dict /out/dict
COPY dataset/which/fuzz/in /out/in
COPY dataset/which/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/which/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/which /out/which.cmplog && \
    file /out/which && \
    /out/which --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing which'"]
