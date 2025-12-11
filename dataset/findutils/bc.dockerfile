FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract findutils v4.10.0
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/findutils/findutils-4.10.0.tar.xz && \
    tar -xJf findutils-4.10.0.tar.xz && \
    rm findutils-4.10.0.tar.xz

WORKDIR /home/SVF-tools/findutils-4.10.0

# Install build dependencies (file for extract-bc, xz for extraction)
RUN apt-get update && \
    apt-get install -y file xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build findutils
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc find/find && \
    extract-bc xargs/xargs && \
    mv find/find.bc ~/bc/ && \
    mv xargs/xargs.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
