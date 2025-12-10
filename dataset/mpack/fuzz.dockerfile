FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract mpack 1.1.1 (amalgamation version)
WORKDIR /src
RUN wget https://github.com/ludocode/mpack/releases/download/v1.1.1/mpack-amalgamation-1.1.1.tar.gz && \
    tar -xzf mpack-amalgamation-1.1.1.tar.gz && \
    rm mpack-amalgamation-1.1.1.tar.gz

WORKDIR /src/mpack-amalgamation-1.1.1

# Copy the fuzzing harness
COPY dataset/mpack/fuzz_mpack.c .

# Compile the fuzzing harness with afl-clang-lto
RUN afl-clang-lto -O2 -DMPACK_READER=1 -DMPACK_EXTENSIONS=1 \
    -static -Wl,--allow-multiple-definition \
    -o fuzz_mpack fuzz_mpack.c src/mpack/mpack.c -lm

# Install the fuzz_mpack binary
RUN cp fuzz_mpack /out/fuzz_mpack

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf mpack-amalgamation-1.1.1 && \
    wget https://github.com/ludocode/mpack/releases/download/v1.1.1/mpack-amalgamation-1.1.1.tar.gz && \
    tar -xzf mpack-amalgamation-1.1.1.tar.gz && \
    rm mpack-amalgamation-1.1.1.tar.gz

WORKDIR /src/mpack-amalgamation-1.1.1

# Copy the fuzzing harness again
COPY dataset/mpack/fuzz_mpack.c .

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -DMPACK_READER=1 -DMPACK_EXTENSIONS=1 \
    -static -Wl,--allow-multiple-definition \
    -o fuzz_mpack fuzz_mpack.c src/mpack/mpack.c -lm

# Install CMPLOG binary
RUN cp fuzz_mpack /out/fuzz_mpack.cmplog

# Copy fuzzing resources
COPY dataset/mpack/fuzz/dict /out/dict
COPY dataset/mpack/fuzz/in /out/in
COPY dataset/mpack/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/mpack/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/fuzz_mpack /out/fuzz_mpack.cmplog && \
    file /out/fuzz_mpack

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing MPack (MessagePack)'"]
