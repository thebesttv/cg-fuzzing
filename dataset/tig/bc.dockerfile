FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tig v2.6.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/jonas/tig/releases/download/tig-2.6.0/tig-2.6.0.tar.gz && \
    tar -xzf tig-2.6.0.tar.gz && \
    rm tig-2.6.0.tar.gz

WORKDIR /home/SVF-tools/tig-2.6.0

# Install build dependencies (file for extract-bc, ncurses for tig, pkg-config)
RUN apt-get update && \
    apt-get install -y file libncurses-dev libreadline-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build tig
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/tig && \
    mv src/tig.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
