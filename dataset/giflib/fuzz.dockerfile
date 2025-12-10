FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract giflib 5.2.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://sourceforge.net/projects/giflib/files/giflib-5.2.2.tar.gz && \
    tar -xzf giflib-5.2.2.tar.gz && \
    rm giflib-5.2.2.tar.gz

WORKDIR /src/giflib-5.2.2

# Build static library first
RUN make CC=afl-clang-lto \
    CFLAGS="-std=gnu99 -Wall -O2" \
    libgif.a

# Build tools with afl-clang-lto for fuzzing
RUN make CC=afl-clang-lto \
    CFLAGS="-std=gnu99 -Wall -O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    giftext gif2rgb gifbuild giftool

# Install binaries
RUN cp giftext /out/giftext

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf giflib-5.2.2 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://sourceforge.net/projects/giflib/files/giflib-5.2.2.tar.gz && \
    tar -xzf giflib-5.2.2.tar.gz && \
    rm giflib-5.2.2.tar.gz

WORKDIR /src/giflib-5.2.2

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-std=gnu99 -Wall -O2" \
    libgif.a

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-std=gnu99 -Wall -O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    giftext

# Install CMPLOG binary
RUN cp giftext /out/giftext.cmplog

# Copy fuzzing resources
COPY giflib/fuzz/dict /out/dict
COPY giflib/fuzz/in /out/in
COPY giflib/fuzz/fuzz.sh /out/fuzz.sh
COPY giflib/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/giftext /out/giftext.cmplog && \
    file /out/giftext

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing giflib'"]
