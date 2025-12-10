FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract ctags v6.2.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/universal-ctags/ctags/releases/download/v6.2.1/universal-ctags-6.2.1.tar.gz && \
    tar -xzf universal-ctags-6.2.1.tar.gz && \
    rm universal-ctags-6.2.1.tar.gz

WORKDIR /src/universal-ctags-6.2.1

# Build ctags with afl-clang-lto for fuzzing (main target binary)
# Disable optional features to simplify static linking
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure \
        --disable-shared \
        --disable-xml \
        --disable-json \
        --disable-yaml \
        --disable-seccomp \
        --disable-pcre2

RUN make -j$(nproc)

# Install the ctags binary
RUN cp ctags /out/ctags

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf universal-ctags-6.2.1 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/universal-ctags/ctags/releases/download/v6.2.1/universal-ctags-6.2.1.tar.gz && \
    tar -xzf universal-ctags-6.2.1.tar.gz && \
    rm universal-ctags-6.2.1.tar.gz

WORKDIR /src/universal-ctags-6.2.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure \
        --disable-shared \
        --disable-xml \
        --disable-json \
        --disable-yaml \
        --disable-seccomp \
        --disable-pcre2

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp ctags /out/ctags.cmplog

# Copy fuzzing resources
COPY ctags/fuzz/dict /out/dict
COPY ctags/fuzz/in /out/in
COPY ctags/fuzz/fuzz.sh /out/fuzz.sh
COPY ctags/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/ctags /out/ctags.cmplog && \
    file /out/ctags && \
    /out/ctags --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing ctags'"]
