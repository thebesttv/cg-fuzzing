FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract GNU patch 2.8
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/patch/patch-2.8.tar.gz && \
    tar -xzf patch-2.8.tar.gz && \
    rm patch-2.8.tar.gz

WORKDIR /home/SVF-tools/patch-2.8

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build patch
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/patch && \
    mv src/patch.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
