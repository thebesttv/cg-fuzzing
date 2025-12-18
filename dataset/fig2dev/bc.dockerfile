FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract fig2dev v3.2.9
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://sourceforge.net/projects/mcj/files/fig2dev-3.2.9.tar.xz && \
    tar -xf fig2dev-3.2.9.tar.xz && \
    rm fig2dev-3.2.9.tar.xz

WORKDIR /home/SVF-tools/fig2dev-3.2.9

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libpng-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build fig2dev
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from fig2dev
RUN mkdir -p ~/bc && \
    extract-bc fig2dev/fig2dev && \
    mv fig2dev/fig2dev.bc ~/bc/ 2>/dev/null || true

# Verify that bc files were created
RUN ls -la ~/bc/
