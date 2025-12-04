FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract bison v3.8.2
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.gz && \
    tar -xzf bison-3.8.2.tar.gz && \
    rm bison-3.8.2.tar.gz

WORKDIR /home/SVF-tools/bison-3.8.2

# Install build dependencies (file for extract-bc, m4 for bison build)
RUN apt-get update && \
    apt-get install -y file m4 flex && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build bison
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/bison && \
    mv src/bison.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
