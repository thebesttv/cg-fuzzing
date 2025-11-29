FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract diffutils 3.12
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/diffutils/diffutils-3.12.tar.gz && \
    tar -xzf diffutils-3.12.tar.gz && \
    rm diffutils-3.12.tar.gz

WORKDIR /home/SVF-tools/diffutils-3.12

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

# Build diffutils
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/diff && \
    mv src/diff.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
