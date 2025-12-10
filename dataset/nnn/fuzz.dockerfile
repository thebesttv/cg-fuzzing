FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev libreadline-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract nnn v5.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jarun/nnn/archive/refs/tags/v5.1.tar.gz && \
    tar -xzf v5.1.tar.gz && \
    rm v5.1.tar.gz

WORKDIR /src/nnn-5.1

# Build nnn with afl-clang-lto for fuzzing
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CFLAGS_OPTIMIZATION="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    make strip -j$(nproc)

# Install the nnn binary
RUN cp nnn /out/nnn

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf nnn-5.1 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jarun/nnn/archive/refs/tags/v5.1.tar.gz && \
    tar -xzf v5.1.tar.gz && \
    rm v5.1.tar.gz

WORKDIR /src/nnn-5.1

RUN CC=afl-clang-lto \
    CFLAGS_OPTIMIZATION="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make strip -j$(nproc)

# Install CMPLOG binary
RUN cp nnn /out/nnn.cmplog

# Copy fuzzing resources
COPY nnn/fuzz/dict /out/dict
COPY nnn/fuzz/in /out/in
COPY nnn/fuzz/fuzz.sh /out/fuzz.sh
COPY nnn/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/nnn /out/nnn.cmplog && \
    file /out/nnn && \
    (/out/nnn --version || true)

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'nnn is an interactive file manager. Fuzzing support is limited. Run ./fuzz.sh if needed.'"]
