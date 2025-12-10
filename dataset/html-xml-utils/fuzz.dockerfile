FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget flex bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract html-xml-utils (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://www.w3.org/Tools/HTML-XML-utils/html-xml-utils-8.6.tar.gz && \
    tar -xzf html-xml-utils-8.6.tar.gz && \
    rm html-xml-utils-8.6.tar.gz

WORKDIR /src/html-xml-utils-8.6

# Build with afl-clang-lto
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)
RUN cp hxnormalize /out/hxnormalize

# Build CMPLOG version
WORKDIR /src
RUN rm -rf html-xml-utils-8.6 && \
    wget https://www.w3.org/Tools/HTML-XML-utils/html-xml-utils-8.6.tar.gz && \
    tar -xzf html-xml-utils-8.6.tar.gz && \
    rm html-xml-utils-8.6.tar.gz

WORKDIR /src/html-xml-utils-8.6

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp hxnormalize /out/hxnormalize.cmplog

# Copy fuzzing resources
COPY dataset/html-xml-utils/fuzz/dict /out/dict
COPY dataset/html-xml-utils/fuzz/in /out/in
COPY dataset/html-xml-utils/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/html-xml-utils/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/hxnormalize /out/hxnormalize.cmplog && \
    file /out/hxnormalize

# Default command
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing hxnormalize'"]
