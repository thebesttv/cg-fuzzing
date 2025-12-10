FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget flex bison libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libpcap v1.10.5
WORKDIR /src
RUN wget https://www.tcpdump.org/release/libpcap-1.10.5.tar.gz && \
    tar -xzf libpcap-1.10.5.tar.gz && \
    rm libpcap-1.10.5.tar.gz

WORKDIR /src/libpcap-1.10.5

# Build libpcap with afl-clang-lto
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)
RUN make install

# Download and extract tcpdump v4.99.5
WORKDIR /src
RUN wget https://www.tcpdump.org/release/tcpdump-4.99.5.tar.gz && \
    tar -xzf tcpdump-4.99.5.tar.gz && \
    rm tcpdump-4.99.5.tar.gz

WORKDIR /src/tcpdump-4.99.5

# Build tcpdump with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN make -j$(nproc)

# Copy the tcpdump binary
RUN cp tcpdump /out/tcpdump

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libpcap-1.10.5 && \
    wget https://www.tcpdump.org/release/libpcap-1.10.5.tar.gz && \
    tar -xzf libpcap-1.10.5.tar.gz && \
    rm libpcap-1.10.5.tar.gz

WORKDIR /src/libpcap-1.10.5

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN make install

WORKDIR /src
RUN rm -rf tcpdump-4.99.5 && \
    wget https://www.tcpdump.org/release/tcpdump-4.99.5.tar.gz && \
    tar -xzf tcpdump-4.99.5.tar.gz && \
    rm tcpdump-4.99.5.tar.gz

WORKDIR /src/tcpdump-4.99.5

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp tcpdump /out/tcpdump.cmplog

# Copy fuzzing resources
COPY dataset/tcpdump/fuzz/dict /out/dict
COPY dataset/tcpdump/fuzz/in /out/in
COPY dataset/tcpdump/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/tcpdump/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/tcpdump /out/tcpdump.cmplog && \
    file /out/tcpdump && \
    /out/tcpdump --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tcpdump'"]
