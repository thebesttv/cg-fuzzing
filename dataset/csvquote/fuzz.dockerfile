FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract csvquote 0.1.5 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/dbro/csvquote/archive/refs/tags/v0.1.5.tar.gz && \
    tar -xzf v0.1.5.tar.gz && \
    rm v0.1.5.tar.gz

WORKDIR /src/csvquote-0.1.5

# Build csvquote with afl-clang-lto for fuzzing
RUN make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

RUN cp csvquote /out/csvquote

# Build CMPLOG version
WORKDIR /src
RUN rm -rf csvquote-0.1.5 && \
    wget https://github.com/dbro/csvquote/archive/refs/tags/v0.1.5.tar.gz && \
    tar -xzf v0.1.5.tar.gz && \
    rm v0.1.5.tar.gz

WORKDIR /src/csvquote-0.1.5

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

RUN cp csvquote /out/csvquote.cmplog

# Copy fuzzing resources
COPY dataset/csvquote/fuzz/dict /out/dict
COPY dataset/csvquote/fuzz/in /out/in
COPY dataset/csvquote/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/csvquote/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/csvquote /out/csvquote.cmplog && \
    file /out/csvquote

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing csvquote'"]
