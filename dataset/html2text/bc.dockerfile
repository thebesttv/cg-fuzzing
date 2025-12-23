FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract html2text v2.3.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: html2text" > /work/proj && \
    echo "version: 2.3.0" >> /work/proj && \
    echo "source: https://github.com/grobian/html2text/releases/download/v2.3.0/html2text-2.3.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/grobian/html2text/releases/download/v2.3.0/html2text-2.3.0.tar.gz && \
    tar -xzf html2text-2.3.0.tar.gz && \
    mv html2text-2.3.0 build && \
    rm html2text-2.3.0.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build html2text
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc html2text && \
    mv html2text.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
