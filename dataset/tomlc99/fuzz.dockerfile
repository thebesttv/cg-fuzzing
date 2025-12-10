FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget unzip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download tomlc99 from master branch (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/cktan/tomlc99/archive/refs/heads/master.zip && \
    unzip master.zip && \
    rm master.zip

WORKDIR /src/tomlc99-master

# Build tomlc99 with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    make -j$(nproc)

# Build toml_cat with static linking
RUN afl-clang-lto -O2 -o toml_cat toml_cat.c libtoml.a \
    -static -Wl,--allow-multiple-definition

# Install the binary
RUN cp toml_cat /out/toml_cat

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf tomlc99-master && \
    wget https://github.com/cktan/tomlc99/archive/refs/heads/master.zip && \
    unzip master.zip && \
    rm master.zip

WORKDIR /src/tomlc99-master

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc)

# Build CMPLOG toml_cat with static linking
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -o toml_cat.cmplog toml_cat.c libtoml.a \
    -static -Wl,--allow-multiple-definition

# Install CMPLOG binary
RUN cp toml_cat.cmplog /out/toml_cat.cmplog

# Copy fuzzing resources
COPY dataset/tomlc99/fuzz/dict /out/dict
COPY dataset/tomlc99/fuzz/in /out/in
COPY dataset/tomlc99/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/tomlc99/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/toml_cat /out/toml_cat.cmplog && \
    file /out/toml_cat

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tomlc99'"]
