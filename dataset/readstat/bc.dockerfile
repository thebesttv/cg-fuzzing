FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract readstat v1.1.9

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: readstat" > /work/proj && \
    echo "version: 1.1.9" >> /work/proj && \
    echo "source: unknown" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 \
    https://github.com/WizardMac/ReadStat/releases/download/v1.1.9/readstat-1.1.9.tar.gz && \
    tar -xzf readstat-1.1.9.tar.gz && \
    mv readstat-1.1.9 build && \
    rm readstat-1.1.9.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Disable pedantic-errors to avoid strict-prototypes error
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes -Wno-strict-prototypes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static

# Build readstat
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc readstat && \
    mv readstat.bc /work/bc/ && \
    extract-bc extract_metadata && \
    mv extract_metadata.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
