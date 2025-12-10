FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract quickjs 2024-01-13
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://bellard.org/quickjs/quickjs-2024-01-13.tar.xz && \
    tar -xJf quickjs-2024-01-13.tar.xz && \
    rm quickjs-2024-01-13.tar.xz

WORKDIR /home/SVF-tools/quickjs-2024-01-13

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build quickjs with WLLVM and static linking
# QuickJS uses a Makefile directly
# Need to define CONFIG_VERSION since Makefile generates it
# Need _GNU_SOURCE for environ and sighandler_t
# Build only qjs target to avoid bignum/example issues
RUN make CC=wllvm \
    CFLAGS="-g -O0 -D_GNU_SOURCE -DCONFIG_VERSION=\\\"2024-01-13\\\"" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    CONFIG_LTO= \
    CONFIG_BIGNUM= \
    qjs \
    -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc qjs && \
    mv qjs.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
