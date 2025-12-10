FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract par v1.53.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget http://www.nicemice.net/par/Par-1.53.0.tar.gz && \
    tar -xzf Par-1.53.0.tar.gz && \
    rm Par-1.53.0.tar.gz

WORKDIR /src/Par-1.53.0

# Build par with afl-clang-lto for fuzzing
RUN afl-clang-lto -c -O2 buffer.c && \
    afl-clang-lto -c -O2 charset.c && \
    afl-clang-lto -c -O2 errmsg.c && \
    afl-clang-lto -c -O2 reformat.c && \
    afl-clang-lto -c -O2 par.c && \
    afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
        buffer.o charset.o errmsg.o reformat.o par.o -o par

# Install the par binary
RUN cp par /out/par

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf Par-1.53.0 && \
    wget http://www.nicemice.net/par/Par-1.53.0.tar.gz && \
    tar -xzf Par-1.53.0.tar.gz && \
    rm Par-1.53.0.tar.gz

WORKDIR /src/Par-1.53.0

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 buffer.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 charset.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 errmsg.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 reformat.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 par.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
        buffer.o charset.o errmsg.o reformat.o par.o -o par

# Install CMPLOG binary
RUN cp par /out/par.cmplog

# Copy fuzzing resources
COPY par/fuzz/dict /out/dict
COPY par/fuzz/in /out/in
COPY par/fuzz/fuzz.sh /out/fuzz.sh
COPY par/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/par /out/par.cmplog && \
    file /out/par && \
    echo "Test:" | /out/par

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing par'"]
