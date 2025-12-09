FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract jo 1.9
WORKDIR /home/SVF-tools
RUN wget https://github.com/jpmens/jo/releases/download/1.9/jo-1.9.tar.gz && \
    tar -xzf jo-1.9.tar.gz && \
    rm jo-1.9.tar.gz

WORKDIR /home/SVF-tools/jo-1.9

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build jo
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc jo && \
    mv jo.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
