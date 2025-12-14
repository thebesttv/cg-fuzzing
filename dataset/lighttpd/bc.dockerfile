FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lighttpd v1.4.82
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.82.tar.gz && \
    tar -xzf lighttpd-1.4.82.tar.gz && \
    rm lighttpd-1.4.82.tar.gz

WORKDIR /home/SVF-tools/lighttpd-1.4.82

# Install build dependencies (file for extract-bc, autotools for lighttpd)
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Generate configure script
RUN ./autogen.sh

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared \
                --without-bzip2 \
                --without-zlib \
                --without-pcre2

# Build lighttpd
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/lighttpd && \
    mv src/lighttpd.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
