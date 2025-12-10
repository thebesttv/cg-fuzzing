FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool gettext autopoint pkg-config libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract procps v4.0.4 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://gitlab.com/procps-ng/procps/-/archive/v4.0.4/procps-v4.0.4.tar.gz && \
    tar -xzf procps-v4.0.4.tar.gz && \
    rm procps-v4.0.4.tar.gz

WORKDIR /src/procps-v4.0.4

# Bootstrap the build system
RUN ./autogen.sh

# Build ps with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-nls

RUN make -j$(nproc)

# Install the ps binary (called pscommand)
RUN cp src/ps/pscommand /out/ps

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf procps-v4.0.4 && \
    wget https://gitlab.com/procps-ng/procps/-/archive/v4.0.4/procps-v4.0.4.tar.gz && \
    tar -xzf procps-v4.0.4.tar.gz && \
    rm procps-v4.0.4.tar.gz

WORKDIR /src/procps-v4.0.4

RUN ./autogen.sh

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --disable-nls

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/ps/pscommand /out/ps.cmplog

# Copy fuzzing resources
COPY dataset/procps/fuzz/dict /out/dict
COPY dataset/procps/fuzz/in /out/in
COPY dataset/procps/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/procps/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/ps /out/ps.cmplog && \
    file /out/ps

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing procps (ps)'"]
