FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract mxml 4.0.4 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/michaelrsweet/mxml/releases/download/v4.0.4/mxml-4.0.4.tar.gz && \
    tar -xzf mxml-4.0.4.tar.gz && \
    rm mxml-4.0.4.tar.gz

WORKDIR /src/mxml-4.0.4

# Copy the fuzzing harness
COPY mxml/fuzz_mxml.c .

# Configure mxml with static linking for AFL++
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Compile the fuzzing harness with afl-clang-lto
RUN afl-clang-lto -O2 -I. -static -Wl,--allow-multiple-definition \
    -o fuzz_mxml fuzz_mxml.c libmxml4.a -lm -lpthread

# Install the fuzz_mxml binary
RUN cp fuzz_mxml /out/fuzz_mxml

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf mxml-4.0.4 && \
    wget https://github.com/michaelrsweet/mxml/releases/download/v4.0.4/mxml-4.0.4.tar.gz && \
    tar -xzf mxml-4.0.4.tar.gz && \
    rm mxml-4.0.4.tar.gz

WORKDIR /src/mxml-4.0.4

# Copy the fuzzing harness again
COPY mxml/fuzz_mxml.c .

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I. -static -Wl,--allow-multiple-definition \
    -o fuzz_mxml fuzz_mxml.c libmxml4.a -lm -lpthread

# Install CMPLOG binary
RUN cp fuzz_mxml /out/fuzz_mxml.cmplog

# Copy fuzzing resources
COPY mxml/fuzz/dict /out/dict
COPY mxml/fuzz/in /out/in
COPY mxml/fuzz/fuzz.sh /out/fuzz.sh
COPY mxml/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/fuzz_mxml /out/fuzz_mxml.cmplog && \
    file /out/fuzz_mxml

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing Mini-XML parser'"]
