FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tre v0.9.0
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/laurikari/tre/releases/download/v0.9.0/tre-0.9.0.tar.gz && \
    tar -xzf tre-0.9.0.tar.gz && \
    rm tre-0.9.0.tar.gz

WORKDIR /home/SVF-tools/tre-0.9.0

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

# Build tre (including agrep)
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from agrep
RUN mkdir -p ~/bc && \
    extract-bc src/agrep && \
    mv src/agrep.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
