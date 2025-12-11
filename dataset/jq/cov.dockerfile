FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
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

# Build jq with llvm-cov instrumentation using clang from aflplusplus
# -fprofile-instr-generate: Generate instrumented code for profiling
# -fcoverage-mapping: Generate coverage mapping data
# Use static linking and builtin oniguruma
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static

# Build jq
RUN make -j$(nproc)

# Copy binary to output directory
RUN cp jq /out/jq

WORKDIR /out

# Verify binary is built
RUN ls -la /out/jq && \
    file /out/jq && \
    /out/jq --version
