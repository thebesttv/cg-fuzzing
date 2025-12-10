FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract screen v5.0.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/screen/screen-5.0.1.tar.gz && \
    tar -xzf screen-5.0.1.tar.gz && \
    rm screen-5.0.1.tar.gz

WORKDIR /src/screen-5.0.1

# Build screen with afl-clang-lto for fuzzing (main target binary)
# Use static linking and disable PAM
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-socket-dir --disable-pam

RUN make -j$(nproc)

# Install the screen binary
RUN cp screen /out/screen

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf screen-5.0.1 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/screen/screen-5.0.1.tar.gz && \
    tar -xzf screen-5.0.1.tar.gz && \
    rm screen-5.0.1.tar.gz

WORKDIR /src/screen-5.0.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-socket-dir --disable-pam

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp screen /out/screen.cmplog

# Copy fuzzing resources
COPY screen/fuzz/dict /out/dict
COPY screen/fuzz/in /out/in
COPY screen/fuzz/fuzz.sh /out/fuzz.sh
COPY screen/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/screen /out/screen.cmplog && \
    file /out/screen && \
    /out/screen -v

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing screen'"]
