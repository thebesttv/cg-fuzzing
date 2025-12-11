FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget meson python3-pip ninja-build && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract serd v0.32.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 \
    https://gitlab.com/drobilla/serd/-/archive/v0.32.2/serd-v0.32.2.tar.gz && \
    tar -xzf serd-v0.32.2.tar.gz && \
    rm serd-v0.32.2.tar.gz

WORKDIR /src/serd-v0.32.2

# Build serd with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    meson setup build \
    --default-library=static \
    -Ddocs=disabled \
    -Dtools=enabled \
    -Dtests=disabled

RUN ninja -C build
RUN cp build/serdi /out/serdi

# Build CMPLOG version
WORKDIR /src
RUN rm -rf serd-v0.32.2 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 \
    https://gitlab.com/drobilla/serd/-/archive/v0.32.2/serd-v0.32.2.tar.gz && \
    tar -xzf serd-v0.32.2.tar.gz && \
    rm serd-v0.32.2.tar.gz

WORKDIR /src/serd-v0.32.2

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    meson setup build \
    --default-library=static \
    -Ddocs=disabled \
    -Dtools=enabled \
    -Dtests=disabled

RUN AFL_LLVM_CMPLOG=1 ninja -C build
RUN cp build/serdi /out/serdi.cmplog

# Copy fuzzing resources
COPY serd/fuzz/dict /out/dict
COPY serd/fuzz/in /out/in
COPY serd/fuzz/fuzz.sh /out/fuzz.sh
COPY serd/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries
RUN ls -la /out/serdi /out/serdi.cmplog && \
    file /out/serdi && \
    /out/serdi --help | head -5 || true

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing serd'"]
