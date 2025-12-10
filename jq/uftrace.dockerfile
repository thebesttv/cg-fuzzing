FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract jq v1.8.1 (same version as bc.dockerfile and fuzz.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz && \
    tar -xzf jq-1.8.1.tar.gz && \
    rm jq-1.8.1.tar.gz

WORKDIR /src/jq-1.8.1

# Build jq with uftrace instrumentation using clang from aflplusplus
# -pg: Enable profiling with mcount calls for uftrace
# -fno-omit-frame-pointer: Preserve frame pointer for accurate tracing
# Note: Cannot use -static with -pg for uftrace as it needs dynamic mcount
# Use builtin oniguruma
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin

# Build and install jq
RUN make -j$(nproc)
RUN make install && ldconfig

# Copy binary to output directory
RUN cp /usr/local/bin/jq /out/jq

WORKDIR /out

# Verify binary is built
RUN ls -la /out/jq && \
    file /out/jq && \
    /out/jq --version

# Test that uftrace can trace the binary, then cleanup
RUN uftrace record /out/jq --version && \
    uftrace report && \
    rm -rf uftrace.data
