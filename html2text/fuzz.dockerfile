FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract html2text v2.3.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/grobian/html2text/releases/download/v2.3.0/html2text-2.3.0.tar.gz && \
    tar -xzf html2text-2.3.0.tar.gz && \
    rm html2text-2.3.0.tar.gz

WORKDIR /src/html2text-2.3.0

# Build html2text with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Install the html2text binary
RUN cp html2text /out/html2text

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf html2text-2.3.0 && \
    wget https://github.com/grobian/html2text/releases/download/v2.3.0/html2text-2.3.0.tar.gz && \
    tar -xzf html2text-2.3.0.tar.gz && \
    rm html2text-2.3.0.tar.gz

WORKDIR /src/html2text-2.3.0

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp html2text /out/html2text.cmplog

# Copy fuzzing resources
COPY html2text/fuzz/dict /out/dict
COPY html2text/fuzz/in /out/in
COPY html2text/fuzz/fuzz.sh /out/fuzz.sh
COPY html2text/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/html2text /out/html2text.cmplog && \
    file /out/html2text && \
    /out/html2text -help | head -1

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing html2text'"]
