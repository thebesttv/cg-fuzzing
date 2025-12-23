FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract remind v06.02.01

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: remind" > /work/proj && \
    echo "version: 06.02.01" >> /work/proj && \
    echo "source: https://dianne.skoll.ca/projects/remind/download/remind-06.02.01.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://dianne.skoll.ca/projects/remind/download/remind-06.02.01.tar.gz && \
    tar -xzf remind-06.02.01.tar.gz && \
    mv remind-06.02.01 build && \
    rm remind-06.02.01.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Use autotools for remind
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build remind
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/remind && \
    mv src/remind.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
