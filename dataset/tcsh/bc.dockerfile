FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tcsh v6.24.16

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: tcsh" > /work/proj && \
    echo "version: 6.24.16" >> /work/proj && \
    echo "source: https://astron.com/pub/tcsh/tcsh-6.24.16.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://astron.com/pub/tcsh/tcsh-6.24.16.tar.gz && \
    tar -xzf tcsh-6.24.16.tar.gz && \
    mv tcsh-6.24.16 build && \
    rm tcsh-6.24.16.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure

# Build tcsh
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc tcsh && \
    mv tcsh.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
