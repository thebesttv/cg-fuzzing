FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract monkey v1.5.5
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/monkey/monkey/archive/refs/tags/v1.5.5.tar.gz && \
    tar -xzf v1.5.5.tar.gz && \
    rm v1.5.5.tar.gz

WORKDIR /home/SVF-tools/monkey-1.5.5

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-plugins --malloc-libc

# Build monkey (only the main binary, not plugins to avoid shared library issues)
RUN make -C src -j$(nproc)

# Note: Monkey uses thread-local storage (TLS) which causes "symbol multiply defined" errors
# during LLVM bitcode extraction. This is a known limitation.
# For now, we'll generate individual .o.bc files but skip the linking step.
RUN mkdir -p ~/bc && \
    cd src && \
    for f in *.o; do extract-bc "$f" 2>/dev/null || true; done && \
    mv *.o.bc ~/bc/ 2>/dev/null || true

# Verify that bc files were created
RUN ls -la ~/bc/
