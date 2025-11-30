FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract remind v06.02.01
WORKDIR /home/SVF-tools
RUN wget https://dianne.skoll.ca/projects/remind/download/remind-06.02.01.tar.gz && \
    tar -xzf remind-06.02.01.tar.gz && \
    rm remind-06.02.01.tar.gz

WORKDIR /home/SVF-tools/remind-06.02.01

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Use autotools for remind
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build remind
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/remind && \
    mv src/remind.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
