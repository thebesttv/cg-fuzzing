FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lrzip v0.651
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ckolivas/lrzip/archive/refs/tags/v0.651.tar.gz && \
    tar -xzf v0.651.tar.gz && \
    rm v0.651.tar.gz

WORKDIR /home/SVF-tools/lrzip-0.651

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool libbz2-dev liblzo2-dev zlib1g-dev liblz4-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Generate configure script
RUN ./autogen.sh

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static

# Build lrzip
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc lrzip && \
    mv lrzip.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
