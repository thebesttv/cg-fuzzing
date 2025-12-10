FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libaio-dev libapparmor-dev libattr1-dev libbsd-dev libcap-dev libgcrypt-dev libipsec-mb-dev libjudy-dev libkeyutils-dev libkmod-dev libsctp-dev libxxhash-dev zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract stress-ng v0.18.05 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/ColinIanKing/stress-ng/archive/V0.18.05.tar.gz && \
    tar -xzf V0.18.05.tar.gz && \
    rm V0.18.05.tar.gz

WORKDIR /src/stress-ng-0.18.05

# Build stress-ng with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc) STATIC=1

# Install the stress-ng binary
RUN cp stress-ng /out/stress-ng

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf stress-ng-0.18.05 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/ColinIanKing/stress-ng/archive/V0.18.05.tar.gz && \
    tar -xzf V0.18.05.tar.gz && \
    rm V0.18.05.tar.gz

WORKDIR /src/stress-ng-0.18.05

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc) STATIC=1

# Install CMPLOG binary
RUN cp stress-ng /out/stress-ng.cmplog

# Copy fuzzing resources
COPY stress-ng/fuzz/dict /out/dict
COPY stress-ng/fuzz/in /out/in
COPY stress-ng/fuzz/fuzz.sh /out/fuzz.sh
COPY stress-ng/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/stress-ng /out/stress-ng.cmplog && \
    file /out/stress-ng

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing stress-ng'"]
