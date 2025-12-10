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

# Download and extract csvquote 0.1.5
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/dbro/csvquote/archive/refs/tags/v0.1.5.tar.gz && \
    tar -xzf v0.1.5.tar.gz && \
    rm v0.1.5.tar.gz

WORKDIR /home/SVF-tools/csvquote-0.1.5

# Build with static linking and WLLVM
# csvquote has a simple Makefile
RUN make CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc csvquote && \
    mv csvquote.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
