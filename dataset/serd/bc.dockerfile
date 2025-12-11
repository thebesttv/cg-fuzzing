FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract serd v0.32.2
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 \
    https://gitlab.com/drobilla/serd/-/archive/v0.32.2/serd-v0.32.2.tar.gz && \
    tar -xzf serd-v0.32.2.tar.gz && \
    rm serd-v0.32.2.tar.gz

WORKDIR /home/SVF-tools/serd-v0.32.2

# Install build dependencies (file for extract-bc, meson for building)
RUN apt-get update && \
    apt-get install -y file meson python3-pip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    meson setup build \
    --default-library=static \
    -Ddocs=disabled \
    -Dtools=enabled \
    -Dtests=disabled

# Build serd
RUN ninja -C build

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc build/serdi && \
    mv build/serdi.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
