FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract wdiff 1.2.2
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/wdiff/wdiff-1.2.2.tar.gz && \
    tar -xzf wdiff-1.2.2.tar.gz && \
    rm wdiff-1.2.2.tar.gz

WORKDIR /home/SVF-tools/wdiff-1.2.2

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build wdiff (skip doc directory which requires makeinfo)
RUN make -C lib -j$(nproc) && \
    make -C po -j$(nproc) && \
    make -C src -j$(nproc)

# Create bc directory and extract bitcode files
# wdiff produces: wdiff, mdiff (for comparing multiple files)
RUN mkdir -p ~/bc && \
    extract-bc src/wdiff && \
    mv src/wdiff.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
