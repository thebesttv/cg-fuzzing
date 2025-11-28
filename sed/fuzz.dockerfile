FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract sed 4.9 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://ftp.gnu.org/gnu/sed/sed-4.9.tar.gz && \
    tar -xzf sed-4.9.tar.gz && \
    rm sed-4.9.tar.gz

WORKDIR /src/sed-4.9

# Build sed with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the sed binary
RUN cp sed/sed /out/sed

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf sed-4.9 && \
    wget https://ftp.gnu.org/gnu/sed/sed-4.9.tar.gz && \
    tar -xzf sed-4.9.tar.gz && \
    rm sed-4.9.tar.gz

WORKDIR /src/sed-4.9

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp sed/sed /out/sed.cmplog

# Copy fuzzing resources
COPY sed/fuzz/dict /out/dict
COPY sed/fuzz/in /out/in
COPY sed/fuzz/fuzz.sh /out/fuzz.sh
COPY sed/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/sed /out/sed.cmplog && \
    file /out/sed && \
    /out/sed --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing sed'"]
