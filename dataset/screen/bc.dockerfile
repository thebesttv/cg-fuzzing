FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract screen v5.0.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: screen" > /work/proj && \
    echo "version: 5.0.1" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/screen/screen-5.0.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/screen/screen-5.0.1.tar.gz && \
    tar -xzf screen-5.0.1.tar.gz && \
    mv screen-5.0.1 build && \
    rm screen-5.0.1.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-socket-dir --disable-pam

# Build screen
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc screen && \
    mv screen.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
