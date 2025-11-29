FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget bison ruby && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download mruby 3.4.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/mruby/mruby/archive/refs/tags/3.4.0.tar.gz && \
    tar -xzf 3.4.0.tar.gz && \
    rm 3.4.0.tar.gz

WORKDIR /src/mruby-3.4.0

# Build mruby with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    rake

# Install the binary
RUN cp build/host/bin/mruby /out/mruby

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf mruby-3.4.0 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/mruby/mruby/archive/refs/tags/3.4.0.tar.gz && \
    tar -xzf 3.4.0.tar.gz && \
    rm 3.4.0.tar.gz

WORKDIR /src/mruby-3.4.0

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    rake

# Install CMPLOG binary
RUN cp build/host/bin/mruby /out/mruby.cmplog

# Copy fuzzing resources
COPY mruby/fuzz/dict /out/dict
COPY mruby/fuzz/in /out/in
COPY mruby/fuzz/fuzz.sh /out/fuzz.sh
COPY mruby/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/mruby /out/mruby.cmplog && \
    file /out/mruby

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing mruby'"]
