FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libz-dev autoconf && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract git v2.52.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/git/git/archive/refs/tags/v2.52.0.tar.gz && \
    tar -xzf v2.52.0.tar.gz && \
    rm v2.52.0.tar.gz

WORKDIR /src/git-2.52.0

# Build git with afl-clang-lto for fuzzing (main target binary)
# Use static linking and disable optional features for cleaner build
# afl-clang-lto provides collision-free instrumentation
RUN make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    NO_OPENSSL=1 \
    NO_CURL=1 \
    NO_EXPAT=1 \
    NO_TCLTK=1 \
    NO_PERL=1 \
    NO_PYTHON=1 \
    NO_GETTEXT=1 \
    NO_ICONV=1 \
    NEEDS_LIBICONV= \
    git

# Install the git binary
RUN cp git /out/git

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf git-2.52.0 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/git/git/archive/refs/tags/v2.52.0.tar.gz && \
    tar -xzf v2.52.0.tar.gz && \
    rm v2.52.0.tar.gz

WORKDIR /src/git-2.52.0

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    NO_OPENSSL=1 \
    NO_CURL=1 \
    NO_EXPAT=1 \
    NO_TCLTK=1 \
    NO_PERL=1 \
    NO_PYTHON=1 \
    NO_GETTEXT=1 \
    NO_ICONV=1 \
    NEEDS_LIBICONV= \
    git

# Install CMPLOG binary
RUN cp git /out/git.cmplog

# Copy fuzzing resources
COPY git/fuzz/dict /out/dict
COPY git/fuzz/in /out/in
COPY git/fuzz/fuzz.sh /out/fuzz.sh
COPY git/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/git /out/git.cmplog && \
    file /out/git && \
    /out/git --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing git'"]
