FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract GNU units 2.24
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/units/units-2.24.tar.gz && \
    tar -xzf units-2.24.tar.gz && \
    rm units-2.24.tar.gz

WORKDIR /home/SVF-tools/units-2.24

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build units
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc units && \
    mv units.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
