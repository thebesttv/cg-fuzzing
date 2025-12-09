FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget pkg-config liblz4-dev zlib1g-dev libzmq3-dev libevent-dev libmsgpack-dev rapidjson-dev libxxhash-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract groonga v15.2.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/groonga/groonga/releases/download/v15.2.1/groonga-15.2.1.tar.gz && \
    tar -xzf groonga-15.2.1.tar.gz && \
    rm groonga-15.2.1.tar.gz

WORKDIR /src/groonga-15.2.1

# Build groonga with afl-clang-lto for fuzzing
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-document --without-mecab

RUN make -j$(nproc)

# Install the groonga binary
RUN cp src/groonga /out/groonga

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf groonga-15.2.1 && \
    wget https://github.com/groonga/groonga/releases/download/v15.2.1/groonga-15.2.1.tar.gz && \
    tar -xzf groonga-15.2.1.tar.gz && \
    rm groonga-15.2.1.tar.gz

WORKDIR /src/groonga-15.2.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --disable-document --without-mecab

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/groonga /out/groonga.cmplog

# Copy fuzzing resources
COPY groonga/fuzz/dict /out/dict
COPY groonga/fuzz/in /out/in
COPY groonga/fuzz/fuzz.sh /out/fuzz.sh
COPY groonga/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/groonga /out/groonga.cmplog && \
    file /out/groonga && \
    /out/groonga --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing groonga'"]
