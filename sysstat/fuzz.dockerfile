FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget gettext && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract sysstat v12.7.6 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/sysstat/sysstat/archive/v12.7.6.tar.gz && \
    tar -xzf v12.7.6.tar.gz && \
    rm v12.7.6.tar.gz

WORKDIR /src/sysstat-12.7.6

# Build sar with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-nls

RUN make -j$(nproc)

# Install the sar binary
RUN cp sar /out/sar

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf sysstat-12.7.6 && \
    wget https://github.com/sysstat/sysstat/archive/v12.7.6.tar.gz && \
    tar -xzf v12.7.6.tar.gz && \
    rm v12.7.6.tar.gz

WORKDIR /src/sysstat-12.7.6

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-nls

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp sar /out/sar.cmplog

# Copy fuzzing resources
COPY sysstat/fuzz/dict /out/dict
COPY sysstat/fuzz/in /out/in
COPY sysstat/fuzz/fuzz.sh /out/fuzz.sh
COPY sysstat/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/sar /out/sar.cmplog && \
    file /out/sar

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing sysstat (sar)'"]
