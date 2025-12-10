FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract antiword (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/grobian/antiword/archive/refs/heads/main.tar.gz -O antiword.tar.gz && \
    tar -xzf antiword.tar.gz && \
    rm antiword.tar.gz

WORKDIR /src/antiword-main

# Build antiword with afl-clang-lto for fuzzing (main target binary)
# Override both CC and LD since Makefile uses separate LD variable
RUN make CC=afl-clang-lto \
    LD=afl-clang-lto \
    CFLAGS="-O2 -DNDEBUG" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Install the antiword binary
RUN cp antiword /out/antiword

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf antiword-main && \
    wget https://github.com/grobian/antiword/archive/refs/heads/main.tar.gz -O antiword.tar.gz && \
    tar -xzf antiword.tar.gz && \
    rm antiword.tar.gz

WORKDIR /src/antiword-main

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    LD=afl-clang-lto \
    CFLAGS="-O2 -DNDEBUG" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Install CMPLOG binary
RUN cp antiword /out/antiword.cmplog

# Copy fuzzing resources
COPY antiword/fuzz/dict /out/dict
COPY antiword/fuzz/in /out/in
COPY antiword/fuzz/fuzz.sh /out/fuzz.sh
COPY antiword/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/antiword /out/antiword.cmplog && \
    file /out/antiword

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing antiword'"]
