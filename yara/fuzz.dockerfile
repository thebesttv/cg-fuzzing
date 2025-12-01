FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool pkg-config flex bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract yara v4.5.5 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.5.tar.gz && \
    tar -xzf v4.5.5.tar.gz && \
    rm v4.5.5.tar.gz

WORKDIR /src/yara-4.5.5

# Bootstrap the project
RUN ./bootstrap.sh

# Patch the acx_pthread check to skip the shared library test
RUN sed -i 's/if test x"\$done" = xno; then/if false; then # patched: skip shared lib check/' configure

# Configure with afl-clang-lto and static linking
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --without-crypto

# Add static flags to the Makefile for linking
RUN sed -i 's/\(yara_LDADD = \)/\1-all-static /' Makefile && \
    sed -i 's/\(yarac_LDADD = \)/\1-all-static /' Makefile

# Build yara
RUN make -j$(nproc)

# Copy the yara binary
RUN cp yara /out/yara

# Build CMPLOG version
WORKDIR /src
RUN rm -rf yara-4.5.5 && \
    wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.5.tar.gz && \
    tar -xzf v4.5.5.tar.gz && \
    rm v4.5.5.tar.gz

WORKDIR /src/yara-4.5.5

RUN ./bootstrap.sh

RUN sed -i 's/if test x"\$done" = xno; then/if false; then # patched: skip shared lib check/' configure

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --without-crypto

RUN sed -i 's/\(yara_LDADD = \)/\1-all-static /' Makefile && \
    sed -i 's/\(yarac_LDADD = \)/\1-all-static /' Makefile

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN cp yara /out/yara.cmplog

# Copy fuzzing resources
COPY yara/fuzz/dict /out/dict
COPY yara/fuzz/in /out/in
COPY yara/fuzz/fuzz.sh /out/fuzz.sh
COPY yara/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/yara /out/yara.cmplog && \
    file /out/yara && \
    /out/yara --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing yara'"]
