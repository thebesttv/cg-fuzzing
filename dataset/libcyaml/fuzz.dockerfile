FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libyaml-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libcyaml 1.4.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget -O libcyaml-1.4.2.tar.gz "https://api.github.com/repos/tlsa/libcyaml/tarball/v1.4.2" && \
    tar -xzf libcyaml-1.4.2.tar.gz && \
    mv tlsa-libcyaml-* libcyaml-1.4.2 && \
    rm libcyaml-1.4.2.tar.gz

WORKDIR /src/libcyaml-1.4.2

# Build libcyaml with afl-clang-lto
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    make -j$(nproc)

# Build numerical example with afl-clang-lto
RUN cd examples/numerical && \
    afl-clang-lto -O2 -I../../include -static -Wl,--allow-multiple-definition \
        -o numerical main.c ../../build/release/libcyaml.a -lyaml

# Copy binary to output
RUN cp examples/numerical/numerical /out/numerical

# Build CMPLOG version
WORKDIR /src
RUN rm -rf libcyaml-1.4.2 && \
    wget -O libcyaml-1.4.2.tar.gz "https://api.github.com/repos/tlsa/libcyaml/tarball/v1.4.2" && \
    tar -xzf libcyaml-1.4.2.tar.gz && \
    mv tlsa-libcyaml-* libcyaml-1.4.2 && \
    rm libcyaml-1.4.2.tar.gz

WORKDIR /src/libcyaml-1.4.2

RUN CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    CFLAGS="-O2" \
    make -j$(nproc)

# Build CMPLOG version
RUN cd examples/numerical && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I../../include -static -Wl,--allow-multiple-definition \
        -o numerical.cmplog main.c ../../build/release/libcyaml.a -lyaml

# Copy CMPLOG binary
RUN cp examples/numerical/numerical.cmplog /out/numerical.cmplog

# Copy fuzzing resources
COPY dataset/libcyaml/fuzz/dict /out/dict
COPY dataset/libcyaml/fuzz/in /out/in
COPY dataset/libcyaml/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libcyaml/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/numerical /out/numerical.cmplog && \
    file /out/numerical

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libcyaml'"]
