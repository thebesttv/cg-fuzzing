FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libhtp v0.5.52
WORKDIR /home/SVF-tools
RUN wget https://github.com/OISF/libhtp/archive/refs/tags/0.5.52.tar.gz && \
    tar -xzf 0.5.52.tar.gz && \
    rm 0.5.52.tar.gz

WORKDIR /home/SVF-tools/libhtp-0.5.52

# Install build dependencies
RUN apt-get update && \
    apt-get install -y autoconf automake libtool pkg-config zlib1g-dev file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Generate configure script
RUN ./autogen.sh

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build libhtp and test tools
RUN make -j$(nproc)

# Build test_fuzz specifically
RUN cd test && make test_fuzz

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc test/test_fuzz && \
    mv test/test_fuzz.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
