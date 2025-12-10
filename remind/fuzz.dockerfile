FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract remind v06.02.01 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://dianne.skoll.ca/projects/remind/download/remind-06.02.01.tar.gz && \
    tar -xzf remind-06.02.01.tar.gz && \
    rm remind-06.02.01.tar.gz

WORKDIR /src/remind-06.02.01

# Build remind with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the remind binary
RUN cp src/remind /out/remind

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf remind-06.02.01 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://dianne.skoll.ca/projects/remind/download/remind-06.02.01.tar.gz && \
    tar -xzf remind-06.02.01.tar.gz && \
    rm remind-06.02.01.tar.gz

WORKDIR /src/remind-06.02.01

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/remind /out/remind.cmplog

# Copy fuzzing resources
COPY remind/fuzz/dict /out/dict
COPY remind/fuzz/in /out/in
COPY remind/fuzz/fuzz.sh /out/fuzz.sh
COPY remind/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/remind /out/remind.cmplog && \
    file /out/remind && \
    /out/remind -v || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing remind'"]
