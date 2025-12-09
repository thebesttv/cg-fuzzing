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

# Download and extract jhead 3.08
WORKDIR /home/SVF-tools
RUN wget https://github.com/Matthias-Wandel/jhead/archive/refs/tags/3.08.tar.gz && \
    tar -xzf 3.08.tar.gz && \
    rm 3.08.tar.gz

WORKDIR /home/SVF-tools/jhead-3.08

# Build jhead with WLLVM for bitcode extraction
# jhead uses a simple Makefile
# Override CFLAGS/LDFLAGS completely to avoid dpkg-buildflags adding LTO flags
RUN make clean 2>/dev/null || true && \
    make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc jhead && \
    mv jhead.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
