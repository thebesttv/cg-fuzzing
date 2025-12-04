FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract GNU ed 1.22
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/ed/ed-1.22.tar.lz && \
    apt-get update && apt-get install -y lzip && \
    tar --lzip -xf ed-1.22.tar.lz && \
    rm ed-1.22.tar.lz && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /home/SVF-tools/ed-1.22

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Note: ed uses a custom configure script, need to set CC explicitly
RUN ./configure CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Build ed
RUN make CC=wllvm CFLAGS="-g -O0 -Xclang -disable-llvm-passes" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc ed && \
    mv ed.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
