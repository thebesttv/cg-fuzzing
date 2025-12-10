FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract expat (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/libexpat/libexpat/releases/download/R_2_7_3/expat-2.7.3.tar.gz && \
    tar -xzf expat-2.7.3.tar.gz && \
    rm expat-2.7.3.tar.gz

WORKDIR /src/expat-2.7.3

# Build expat with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --without-docbook

RUN make -j$(nproc)

# Copy the xmlwf binary
RUN cp xmlwf/xmlwf /out/xmlwf

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf expat-2.7.3 && \
    wget https://github.com/libexpat/libexpat/releases/download/R_2_7_3/expat-2.7.3.tar.gz && \
    tar -xzf expat-2.7.3.tar.gz && \
    rm expat-2.7.3.tar.gz

WORKDIR /src/expat-2.7.3

RUN AFL_LLVM_CMPLOG=1 CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --without-docbook

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp xmlwf/xmlwf /out/xmlwf.cmplog

# Copy fuzzing resources
COPY dataset/expat/fuzz/dict /out/dict
COPY dataset/expat/fuzz/in /out/in
COPY dataset/expat/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/expat/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/xmlwf /out/xmlwf.cmplog && \
    file /out/xmlwf && \
    /out/xmlwf --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing expat'"]
