FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract unifdef 2.12 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://dotat.at/prog/unifdef/unifdef-2.12.tar.gz && \
    tar -xzf unifdef-2.12.tar.gz && \
    rm unifdef-2.12.tar.gz

WORKDIR /src/unifdef-2.12

# Build unifdef with afl-clang-lto for fuzzing (main target binary)
RUN make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition"

# Install the unifdef binary
RUN cp unifdef /out/unifdef

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf unifdef-2.12 && \
    wget https://dotat.at/prog/unifdef/unifdef-2.12.tar.gz && \
    tar -xzf unifdef-2.12.tar.gz && \
    rm unifdef-2.12.tar.gz

WORKDIR /src/unifdef-2.12

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition"

# Install CMPLOG binary
RUN cp unifdef /out/unifdef.cmplog

# Copy fuzzing resources
COPY unifdef/fuzz/dict /out/dict
COPY unifdef/fuzz/in /out/in
COPY unifdef/fuzz/fuzz.sh /out/fuzz.sh
COPY unifdef/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/unifdef /out/unifdef.cmplog && \
    file /out/unifdef && \
    /out/unifdef --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing unifdef'"]
