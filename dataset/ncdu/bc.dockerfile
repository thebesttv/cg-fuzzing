FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract ncdu 1.22
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://dev.yorhel.nl/download/ncdu-1.22.tar.gz && \
    tar -xzf ncdu-1.22.tar.gz && \
    rm ncdu-1.22.tar.gz

WORKDIR /home/SVF-tools/ncdu-1.22

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libncurses-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build ncdu
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    for bin in ncdu; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
