FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract SQLite version-3.51.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/sqlite/sqlite/archive/refs/tags/version-3.51.0.tar.gz && \
    tar -xzf version-3.51.0.tar.gz && \
    rm version-3.51.0.tar.gz

WORKDIR /home/SVF-tools/sqlite-version-3.51.0

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Disable TCL extension and shared libraries to avoid conflicts with static linking
# Note: --allow-multiple-definition is required for static linking with glibc
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-tcl --disable-shared --enable-static

# Build only the sqlite3 CLI (avoid building shared libraries)
RUN make sqlite3 -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    if [ -f "sqlite3" ] && [ -x "sqlite3" ] && file "sqlite3" | grep -q "ELF"; then \
        extract-bc "sqlite3" && \
        mv "sqlite3.bc" ~/bc/ 2>/dev/null || true; \
    fi

# Verify that bc files were created
RUN ls -la ~/bc/
