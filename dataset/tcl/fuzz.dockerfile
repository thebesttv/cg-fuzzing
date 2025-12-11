FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract Tcl v8.6.15 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://prdownloads.sourceforge.net/tcl/tcl8.6.15-src.tar.gz && \
    tar -xzf tcl8.6.15-src.tar.gz && \
    rm tcl8.6.15-src.tar.gz

WORKDIR /src/tcl8.6.15/unix

# Build tclsh with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc) tclsh

# Copy the tclsh binary
RUN cp tclsh /out/tclsh

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf tcl8.6.15 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://prdownloads.sourceforge.net/tcl/tcl8.6.15-src.tar.gz && \
    tar -xzf tcl8.6.15-src.tar.gz && \
    rm tcl8.6.15-src.tar.gz

WORKDIR /src/tcl8.6.15/unix

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc) tclsh

# Copy CMPLOG binary
RUN cp tclsh /out/tclsh.cmplog

# Copy fuzzing resources
COPY tcl/fuzz/dict /out/dict
COPY tcl/fuzz/in /out/in
COPY tcl/fuzz/fuzz.sh /out/fuzz.sh
COPY tcl/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/tclsh /out/tclsh.cmplog && \
    file /out/tclsh

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tclsh'"]
