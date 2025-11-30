FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
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

# Install build dependencies (file for extract-bc, libncurses for tig)
RUN apt-get update && \
    apt-get install -y file libncurses-dev libncurses5-dev libreadline-dev git pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --prefix=/usr --sysconfdir=/etc --with-ncurses

# Build tig
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/tig && \
    mv src/tig.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
