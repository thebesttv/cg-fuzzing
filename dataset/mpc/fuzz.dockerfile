FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract mpc v0.9.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/orangeduck/mpc/archive/refs/tags/0.9.0.tar.gz && \
    tar -xzf 0.9.0.tar.gz && \
    rm 0.9.0.tar.gz

WORKDIR /src/mpc-0.9.0

# Build with afl-clang-lto for fuzzing
RUN afl-clang-lto -O2 -ansi -pedantic -Wall \
    -static -Wl,--allow-multiple-definition \
    examples/maths.c mpc.c -lm -o maths

# Install the maths binary
RUN cp maths /out/maths

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf mpc-0.9.0 && \
    wget https://github.com/orangeduck/mpc/archive/refs/tags/0.9.0.tar.gz && \
    tar -xzf 0.9.0.tar.gz && \
    rm 0.9.0.tar.gz

WORKDIR /src/mpc-0.9.0

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -ansi -pedantic -Wall \
    -static -Wl,--allow-multiple-definition \
    examples/maths.c mpc.c -lm -o maths.cmplog

# Install CMPLOG binary
RUN cp maths.cmplog /out/maths.cmplog

# Copy fuzzing resources
COPY dataset/mpc/fuzz/dict /out/dict
COPY dataset/mpc/fuzz/in /out/in
COPY dataset/mpc/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/mpc/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/maths /out/maths.cmplog && \
    file /out/maths

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing mpc'"]
