FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract optipng 0.7.8 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://sourceforge.net/projects/optipng/files/OptiPNG/optipng-0.7.8/optipng-0.7.8.tar.gz && \
    tar -xzf optipng-0.7.8.tar.gz && \
    rm optipng-0.7.8.tar.gz

WORKDIR /src/optipng-0.7.8

# Build optipng with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the binary
RUN cp src/optipng/optipng /out/optipng

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf optipng-0.7.8 && \
    wget https://sourceforge.net/projects/optipng/files/OptiPNG/optipng-0.7.8/optipng-0.7.8.tar.gz && \
    tar -xzf optipng-0.7.8.tar.gz && \
    rm optipng-0.7.8.tar.gz

WORKDIR /src/optipng-0.7.8

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/optipng/optipng /out/optipng.cmplog

# Copy fuzzing resources
COPY dataset/optipng/fuzz/dict /out/dict
COPY dataset/optipng/fuzz/in /out/in
COPY dataset/optipng/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/optipng/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/optipng /out/optipng.cmplog && \
    file /out/optipng && \
    /out/optipng --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing optipng'"]
