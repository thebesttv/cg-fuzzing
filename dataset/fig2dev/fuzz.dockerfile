FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libpng-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract fig2dev v3.2.9 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://sourceforge.net/projects/mcj/files/fig2dev-3.2.9.tar.xz && \
    tar -xf fig2dev-3.2.9.tar.xz && \
    rm fig2dev-3.2.9.tar.xz

WORKDIR /src/fig2dev-3.2.9

# Build fig2dev with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Copy the fig2dev binary
RUN cp fig2dev/fig2dev /out/fig2dev

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf fig2dev-3.2.9 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://sourceforge.net/projects/mcj/files/fig2dev-3.2.9.tar.xz && \
    tar -xf fig2dev-3.2.9.tar.xz && \
    rm fig2dev-3.2.9.tar.xz

WORKDIR /src/fig2dev-3.2.9

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp fig2dev/fig2dev /out/fig2dev.cmplog

# Copy fuzzing resources
COPY dataset/fig2dev/fuzz/dict /out/dict
COPY dataset/fig2dev/fuzz/in /out/in
COPY dataset/fig2dev/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/fig2dev/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/fig2dev /out/fig2dev.cmplog && \
    file /out/fig2dev

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing fig2dev'"]
