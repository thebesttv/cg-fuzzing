FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract mandoc 1.14.6 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://mandoc.bsd.lv/snapshots/mandoc.tar.gz && \
    tar -xzf mandoc.tar.gz && \
    rm mandoc.tar.gz

WORKDIR /src/mandoc-1.14.6

# Configure mandoc with afl-clang-lto
RUN printf 'CC=afl-clang-lto\nCFLAGS="-O2"\nLDFLAGS="-static -Wl,--allow-multiple-definition"\nSTATIC=-static\n' > configure.local

RUN ./configure
RUN make mandoc -j$(nproc)
RUN cp mandoc /out/mandoc

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf mandoc-1.14.6 && \
    wget https://mandoc.bsd.lv/snapshots/mandoc.tar.gz && \
    tar -xzf mandoc.tar.gz && \
    rm mandoc.tar.gz

WORKDIR /src/mandoc-1.14.6

RUN printf 'CC=afl-clang-lto\nCFLAGS="-O2"\nLDFLAGS="-static -Wl,--allow-multiple-definition"\nSTATIC=-static\n' > configure.local

RUN AFL_LLVM_CMPLOG=1 ./configure
RUN AFL_LLVM_CMPLOG=1 make mandoc -j$(nproc)
RUN cp mandoc /out/mandoc.cmplog

# Copy fuzzing resources
COPY dataset/mandoc/fuzz/dict /out/dict
COPY dataset/mandoc/fuzz/in /out/in
COPY dataset/mandoc/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/mandoc/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/mandoc /out/mandoc.cmplog && \
    file /out/mandoc && \
    /out/mandoc --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing mandoc'"]
