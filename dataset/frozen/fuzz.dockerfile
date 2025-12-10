FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract frozen 1.7 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/cesanta/frozen/archive/refs/tags/1.7.tar.gz && \
    tar -xzf 1.7.tar.gz && \
    rm 1.7.tar.gz

WORKDIR /src/frozen-1.7

# Copy the fuzzing harness
COPY dataset/frozen/fuzz_json.c .

# Build fuzz_json with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
    -o fuzz_json fuzz_json.c frozen.c -lm

# Install the fuzz_json binary
RUN cp fuzz_json /out/fuzz_json

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf frozen-1.7 && \
    wget https://github.com/cesanta/frozen/archive/refs/tags/1.7.tar.gz && \
    tar -xzf 1.7.tar.gz && \
    rm 1.7.tar.gz

WORKDIR /src/frozen-1.7

# Copy the fuzzing harness again
COPY dataset/frozen/fuzz_json.c .

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
    -o fuzz_json fuzz_json.c frozen.c -lm

# Install CMPLOG binary
RUN cp fuzz_json /out/fuzz_json.cmplog

# Copy fuzzing resources
COPY dataset/frozen/fuzz/dict /out/dict
COPY dataset/frozen/fuzz/in /out/in
COPY dataset/frozen/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/frozen/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/fuzz_json /out/fuzz_json.cmplog && \
    file /out/fuzz_json

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing frozen JSON parser'"]
