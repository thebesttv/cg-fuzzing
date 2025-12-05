FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tcpdump v4.99.5
WORKDIR /home/SVF-tools
RUN wget https://www.tcpdump.org/release/tcpdump-4.99.5.tar.gz && \
    tar -xzf tcpdump-4.99.5.tar.gz && \
    rm tcpdump-4.99.5.tar.gz

# Download and build libpcap (required dependency)
RUN wget https://www.tcpdump.org/release/libpcap-1.10.5.tar.gz && \
    tar -xzf libpcap-1.10.5.tar.gz && \
    rm libpcap-1.10.5.tar.gz

WORKDIR /home/SVF-tools/libpcap-1.10.5

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file flex bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build libpcap statically
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Install libpcap
RUN make install

# Build tcpdump
WORKDIR /home/SVF-tools/tcpdump-4.99.5

RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc tcpdump && \
    mv tcpdump.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
