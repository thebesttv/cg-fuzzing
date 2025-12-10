FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract odt2txt v0.5 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/dstosberg/odt2txt/archive/refs/tags/v0.5.tar.gz && \
    tar -xzf v0.5.tar.gz && \
    rm v0.5.tar.gz

WORKDIR /src/odt2txt-0.5

# Build odt2txt with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    make

# Install the odt2txt binary
RUN cp odt2txt /out/odt2txt

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf odt2txt-0.5 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/dstosberg/odt2txt/archive/refs/tags/v0.5.tar.gz && \
    tar -xzf v0.5.tar.gz && \
    rm v0.5.tar.gz

WORKDIR /src/odt2txt-0.5

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make

# Install CMPLOG binary
RUN cp odt2txt /out/odt2txt.cmplog

# Copy fuzzing resources
COPY odt2txt/fuzz/dict /out/dict
COPY odt2txt/fuzz/in /out/in
COPY odt2txt/fuzz/fuzz.sh /out/fuzz.sh
COPY odt2txt/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/odt2txt /out/odt2txt.cmplog && \
    file /out/odt2txt && \
    /out/odt2txt --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing odt2txt'"]
