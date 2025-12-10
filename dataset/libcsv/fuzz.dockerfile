FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libcsv 3.0.3 (same version as bc.dockerfile)
WORKDIR /src
RUN wget -O libcsv-3.0.3.tar.gz "https://sourceforge.net/projects/libcsv/files/libcsv/libcsv-3.0.3/libcsv-3.0.3.tar.gz/download" && \
    tar -xzf libcsv-3.0.3.tar.gz && \
    rm libcsv-3.0.3.tar.gz

WORKDIR /src/libcsv-3.0.3

# Build libcsv with afl-clang-lto
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Build example tools with afl-clang-lto
# Fix include path: examples use "libcsv/csv.h" but header is at ./csv.h
RUN mkdir -p libcsv && cp csv.h libcsv/csv.h && \
    cd examples && \
    afl-clang-lto -O2 -I.. -static -Wl,--allow-multiple-definition -o csvinfo csvinfo.c ../.libs/libcsv.a && \
    afl-clang-lto -O2 -I.. -static -Wl,--allow-multiple-definition -o csvvalid csvvalid.c ../.libs/libcsv.a && \
    afl-clang-lto -O2 -I.. -static -Wl,--allow-multiple-definition -o csvfix csvfix.c ../.libs/libcsv.a

# Copy binaries to output
RUN cp examples/csvinfo /out/csvinfo && \
    cp examples/csvvalid /out/csvvalid && \
    cp examples/csvfix /out/csvfix

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf libcsv-3.0.3 && \
    wget -O libcsv-3.0.3.tar.gz "https://sourceforge.net/projects/libcsv/files/libcsv/libcsv-3.0.3/libcsv-3.0.3.tar.gz/download" && \
    tar -xzf libcsv-3.0.3.tar.gz && \
    rm libcsv-3.0.3.tar.gz

WORKDIR /src/libcsv-3.0.3

RUN CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build CMPLOG example tools
RUN mkdir -p libcsv && cp csv.h libcsv/csv.h && \
    cd examples && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I.. -static -Wl,--allow-multiple-definition -o csvinfo.cmplog csvinfo.c ../.libs/libcsv.a && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I.. -static -Wl,--allow-multiple-definition -o csvvalid.cmplog csvvalid.c ../.libs/libcsv.a

# Copy CMPLOG binaries
RUN cp examples/csvinfo.cmplog /out/csvinfo.cmplog && \
    cp examples/csvvalid.cmplog /out/csvvalid.cmplog

# Copy fuzzing resources
COPY dataset/libcsv/fuzz/dict /out/dict
COPY dataset/libcsv/fuzz/in /out/in
COPY dataset/libcsv/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libcsv/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/csvinfo /out/csvinfo.cmplog /out/csvvalid && \
    file /out/csvinfo && \
    echo "test,data" > /tmp/test.csv && /out/csvinfo /tmp/test.csv

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libcsv'"]
