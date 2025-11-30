FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract mg v3.7
WORKDIR /home/SVF-tools
RUN wget https://github.com/troglobit/mg/releases/download/v3.7/mg-3.7.tar.gz && \
    tar -xzf mg-3.7.tar.gz && \
    rm mg-3.7.tar.gz

WORKDIR /home/SVF-tools/mg-3.7

# Install build dependencies (file for extract-bc, ncurses for mg)
RUN apt-get update && \
    apt-get install -y file libncurses-dev libncurses5-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --prefix=/usr

# Build mg
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
# mg binary is built in src/ directory
RUN mkdir -p ~/bc && \
    extract-bc src/mg && \
    mv src/mg.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
