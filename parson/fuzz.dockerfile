FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download parson from GitHub (version 1.5.3, same as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/kgabis/parson/archive/ba29f4eda9ea7703a9f6a9cf2b0532a2605723c3.tar.gz -O parson.tar.gz && \
    tar -xzf parson.tar.gz && \
    rm parson.tar.gz && \
    mv parson-ba29f4eda9ea7703a9f6a9cf2b0532a2605723c3 parson

WORKDIR /src/parson

# Copy the harness
COPY parson/fuzz/harness.c harness.c

# Build parson with afl-clang-lto for fuzzing
RUN afl-clang-lto -O2 -c parson.c -o parson.o

# Build the harness with static linking
RUN afl-clang-lto -O2 -I. harness.c parson.o -o parson_harness \
    -static -Wl,--allow-multiple-definition

# Install the binary
RUN cp parson_harness /out/parson_harness

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf parson && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/kgabis/parson/archive/ba29f4eda9ea7703a9f6a9cf2b0532a2605723c3.tar.gz -O parson.tar.gz && \
    tar -xzf parson.tar.gz && \
    rm parson.tar.gz && \
    mv parson-ba29f4eda9ea7703a9f6a9cf2b0532a2605723c3 parson

WORKDIR /src/parson

# Copy the harness again
COPY parson/fuzz/harness.c harness.c

# Build CMPLOG version
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -c parson.c -o parson.o

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I. harness.c parson.o -o parson_harness.cmplog \
    -static -Wl,--allow-multiple-definition

# Install CMPLOG binary
RUN cp parson_harness.cmplog /out/parson_harness.cmplog

# Copy fuzzing resources
COPY parson/fuzz/dict /out/dict
COPY parson/fuzz/in /out/in
COPY parson/fuzz/fuzz.sh /out/fuzz.sh
COPY parson/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/parson_harness /out/parson_harness.cmplog && \
    file /out/parson_harness

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing parson'"]
