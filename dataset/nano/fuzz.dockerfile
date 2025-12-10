FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract nano 8.7 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://www.nano-editor.org/dist/v8/nano-8.7.tar.xz && \
    tar -xf nano-8.7.tar.xz && \
    rm nano-8.7.tar.xz

WORKDIR /src/nano-8.7

# Build nano with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the nano binary
RUN cp src/nano /out/nano

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf nano-8.7 && \
    wget https://www.nano-editor.org/dist/v8/nano-8.7.tar.xz && \
    tar -xf nano-8.7.tar.xz && \
    rm nano-8.7.tar.xz

WORKDIR /src/nano-8.7

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/nano /out/nano.cmplog

# Copy fuzzing resources
COPY dataset/nano/fuzz/dict /out/dict
COPY dataset/nano/fuzz/in /out/in
COPY dataset/nano/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/nano/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/nano /out/nano.cmplog && \
    file /out/nano && \
    /out/nano --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing nano'"]
