FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract dash v0.5.12 (same version as bc.dockerfile)
WORKDIR /src
RUN wget http://gondor.apana.org.au/~herbert/dash/files/dash-0.5.12.tar.gz && \
    tar -xzf dash-0.5.12.tar.gz && \
    rm dash-0.5.12.tar.gz

WORKDIR /src/dash-0.5.12

# Build dash with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the dash binary
RUN cp src/dash /out/dash

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf dash-0.5.12 && \
    wget http://gondor.apana.org.au/~herbert/dash/files/dash-0.5.12.tar.gz && \
    tar -xzf dash-0.5.12.tar.gz && \
    rm dash-0.5.12.tar.gz

WORKDIR /src/dash-0.5.12

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/dash /out/dash.cmplog

# Copy fuzzing resources
COPY dataset/dash/fuzz/dict /out/dict
COPY dataset/dash/fuzz/in /out/in
COPY dataset/dash/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/dash/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/dash /out/dash.cmplog && \
    file /out/dash && \
    /out/dash -c 'echo test'

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing dash'"]
