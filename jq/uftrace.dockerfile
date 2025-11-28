FROM svftools/svf:latest

# Install build dependencies (file for verification, uftrace for tracing)
RUN apt-get update && \
    apt-get install -y file uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Download and extract jq v1.8.1 (same version as bc.dockerfile)
WORKDIR /home/SVF-tools
RUN wget https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz && \
    tar -xzf jq-1.8.1.tar.gz && \
    rm jq-1.8.1.tar.gz

WORKDIR /home/SVF-tools/jq-1.8.1

# Build jq with uftrace instrumentation
# -pg: Enable profiling with mcount calls for uftrace
# -fno-omit-frame-pointer: Preserve frame pointer for accurate tracing
# Note: Cannot use -static with -pg for uftrace as it needs dynamic mcount
# Use builtin oniguruma
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin

# Build and install jq
RUN make -j$(nproc)
RUN make install && ldconfig

# Create uftrace directory and copy binary
# Copy from install location since dynamic linking creates libtool wrapper
RUN mkdir -p ~/uftrace && \
    cp /usr/local/bin/jq ~/uftrace/

# Verify binary is built
RUN ls -la ~/uftrace/jq && \
    file ~/uftrace/jq && \
    ~/uftrace/jq --version

# Test that uftrace can trace the binary, then cleanup
RUN uftrace record ~/uftrace/jq --version && \
    uftrace report && \
    rm -rf uftrace.data
