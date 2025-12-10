FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract GNU enscript 1.6.6
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/enscript/enscript-1.6.6.tar.gz && \
    tar -xzf enscript-1.6.6.tar.gz && \
    rm enscript-1.6.6.tar.gz

WORKDIR /home/SVF-tools/enscript-1.6.6

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build enscript
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/enscript && \
    mv src/enscript.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
