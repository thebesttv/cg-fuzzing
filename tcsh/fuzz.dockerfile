FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract tcsh v6.24.16 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://astron.com/pub/tcsh/tcsh-6.24.16.tar.gz && \
    tar -xzf tcsh-6.24.16.tar.gz && \
    rm tcsh-6.24.16.tar.gz

WORKDIR /src/tcsh-6.24.16

# Build tcsh with afl-clang-lto for fuzzing (main target binary)
# Use static linking for better portability
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the tcsh binary
RUN cp tcsh /out/tcsh

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf tcsh-6.24.16 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://astron.com/pub/tcsh/tcsh-6.24.16.tar.gz && \
    tar -xzf tcsh-6.24.16.tar.gz && \
    rm tcsh-6.24.16.tar.gz

WORKDIR /src/tcsh-6.24.16

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp tcsh /out/tcsh.cmplog

# Copy fuzzing resources
COPY tcsh/fuzz/dict /out/dict
COPY tcsh/fuzz/in /out/in
COPY tcsh/fuzz/fuzz.sh /out/fuzz.sh
COPY tcsh/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/tcsh /out/tcsh.cmplog && \
    file /out/tcsh && \
    echo "exit" | /out/tcsh

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tcsh'"]
