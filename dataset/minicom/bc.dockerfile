FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract minicom v2.9

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: minicom" > /work/proj && \
    echo "version: 2.9" >> /work/proj && \
    echo "source: https://salsa.debian.org/minicom-team/minicom/-/archive/2.9/minicom-2.9.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://salsa.debian.org/minicom-team/minicom/-/archive/2.9/minicom-2.9.tar.gz && \
    tar -xzf minicom-2.9.tar.gz && \
    mv minicom-2.9 build && \
    rm minicom-2.9.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file autoconf automake gettext libncurses-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Run autogen to generate configure
RUN ./autogen.sh

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build minicom
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/minicom && \
    mv src/minicom.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
