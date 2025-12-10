FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget lzip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract GNU ed 1.22 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/ed/ed-1.22.tar.lz && \
    tar --lzip -xf ed-1.22.tar.lz && \
    rm ed-1.22.tar.lz

WORKDIR /src/ed-1.22

# Build ed with afl-clang-lto for fuzzing (main target binary)
RUN ./configure CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

RUN make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Install the ed binary
RUN cp ed /out/ed

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf ed-1.22 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/ed/ed-1.22.tar.lz && \
    tar --lzip -xf ed-1.22.tar.lz && \
    rm ed-1.22.tar.lz

WORKDIR /src/ed-1.22

RUN AFL_LLVM_CMPLOG=1 ./configure CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Install CMPLOG binary
RUN cp ed /out/ed.cmplog

# Copy fuzzing resources
COPY ed/fuzz/dict /out/dict
COPY ed/fuzz/in /out/in
COPY ed/fuzz/fuzz.sh /out/fuzz.sh
COPY ed/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/ed /out/ed.cmplog && \
    file /out/ed && \
    /out/ed --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing ed'"]
