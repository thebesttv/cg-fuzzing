FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libpng-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract jbig2dec v0.20 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/ArtifexSoftware/jbig2dec/archive/refs/tags/0.20.tar.gz -O jbig2dec-0.20.tar.gz && \
    tar -xzf jbig2dec-0.20.tar.gz && \
    rm jbig2dec-0.20.tar.gz

WORKDIR /src/jbig2dec-0.20

# Build jbig2dec with afl-clang-lto
RUN make -f Makefile.unix \
    CC=afl-clang-lto \
    CFLAGS="-O2 -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    jbig2dec

# Install the jbig2dec binary
RUN cp jbig2dec /out/jbig2dec

# Build CMPLOG version
WORKDIR /src
RUN rm -rf jbig2dec-0.20 && \
    wget https://github.com/ArtifexSoftware/jbig2dec/archive/refs/tags/0.20.tar.gz -O jbig2dec-0.20.tar.gz && \
    tar -xzf jbig2dec-0.20.tar.gz && \
    rm jbig2dec-0.20.tar.gz

WORKDIR /src/jbig2dec-0.20

RUN AFL_LLVM_CMPLOG=1 make -f Makefile.unix \
    CC=afl-clang-lto \
    CFLAGS="-O2 -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    jbig2dec

# Install CMPLOG binary
RUN cp jbig2dec /out/jbig2dec.cmplog

# Copy fuzzing resources
COPY jbig2dec/fuzz/dict /out/dict
COPY jbig2dec/fuzz/in /out/in
COPY jbig2dec/fuzz/fuzz.sh /out/fuzz.sh
COPY jbig2dec/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/jbig2dec /out/jbig2dec.cmplog && \
    file /out/jbig2dec && \
    /out/jbig2dec --help || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing jbig2dec'"]
