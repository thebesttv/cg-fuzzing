FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract pcre2 10.47 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.47/pcre2-10.47.tar.gz && \
    tar -xzf pcre2-10.47.tar.gz && \
    rm pcre2-10.47.tar.gz

WORKDIR /src/pcre2-10.47

# Build with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Install the pcre2grep binary
RUN cp pcre2grep /out/pcre2grep

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf pcre2-10.47 && \
    wget https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.47/pcre2-10.47.tar.gz && \
    tar -xzf pcre2-10.47.tar.gz && \
    rm pcre2-10.47.tar.gz

WORKDIR /src/pcre2-10.47

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp pcre2grep /out/pcre2grep.cmplog

# Copy fuzzing resources
COPY pcre2/fuzz/dict /out/dict
COPY pcre2/fuzz/in /out/in
COPY pcre2/fuzz/fuzz.sh /out/fuzz.sh
COPY pcre2/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/pcre2grep /out/pcre2grep.cmplog && \
    file /out/pcre2grep && \
    /out/pcre2grep --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing pcre2 (pcre2grep)'"]
