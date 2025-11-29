FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract flex v2.6.4
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz && \
    tar -xzf flex-2.6.4.tar.gz && \
    rm flex-2.6.4.tar.gz

WORKDIR /home/SVF-tools/flex-2.6.4

# Install build dependencies (file for extract-bc, m4 for flex build)
RUN apt-get update && \
    apt-get install -y file m4 bison help2man && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build flex
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/flex && \
    mv src/flex.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
