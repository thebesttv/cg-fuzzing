FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract less v668 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://greenwoodsoftware.com/less/less-668.tar.gz && \
    tar -xzf less-668.tar.gz && \
    rm less-668.tar.gz

WORKDIR /src/less-668

# Build less with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --with-regex=posix

RUN make -j$(nproc)

# Install the less binary
RUN cp less /out/less

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf less-668 && \
    wget https://greenwoodsoftware.com/less/less-668.tar.gz && \
    tar -xzf less-668.tar.gz && \
    rm less-668.tar.gz

WORKDIR /src/less-668

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --with-regex=posix

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp less /out/less.cmplog

# Copy fuzzing resources
COPY less/fuzz/dict /out/dict
COPY less/fuzz/in /out/in
COPY less/fuzz/fuzz.sh /out/fuzz.sh
COPY less/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/less /out/less.cmplog && \
    file /out/less && \
    /out/less --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing less'"]
