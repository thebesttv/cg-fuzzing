FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract gawk 5.3.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://ftp.gnu.org/gnu/gawk/gawk-5.3.2.tar.gz && \
    tar -xzf gawk-5.3.2.tar.gz && \
    rm gawk-5.3.2.tar.gz

WORKDIR /src/gawk-5.3.2

# Build gawk with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --disable-extensions

RUN make -j$(nproc)

# Install the gawk binary
RUN cp gawk /out/gawk

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf gawk-5.3.2 && \
    wget https://ftp.gnu.org/gnu/gawk/gawk-5.3.2.tar.gz && \
    tar -xzf gawk-5.3.2.tar.gz && \
    rm gawk-5.3.2.tar.gz

WORKDIR /src/gawk-5.3.2

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --disable-extensions

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp gawk /out/gawk.cmplog

# Copy fuzzing resources
COPY gawk/fuzz/dict /out/dict
COPY gawk/fuzz/in /out/in
COPY gawk/fuzz/fuzz.sh /out/fuzz.sh
COPY gawk/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/gawk /out/gawk.cmplog && \
    file /out/gawk && \
    /out/gawk --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing gawk'"]
