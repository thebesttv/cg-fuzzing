FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract SQLite version-3.51.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: sqlite" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: https://github.com/sqlite/sqlite/archive/refs/tags/version-3.51.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/sqlite/sqlite/archive/refs/tags/version-3.51.0.tar.gz && \
    tar -xzf version-3.51.0.tar.gz && \
    mv version-3.51.0 build && \
    rm version-3.51.0.tar.gz

WORKDIR /work/build

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
RUN mkdir -p /work/bc && \
    if [ -f "sqlite3" ] && [ -x "sqlite3" ] && file "sqlite3" | grep -q "ELF"; then \
        extract-bc "sqlite3" && \
        mv "sqlite3.bc" /work/bc/ 2>/dev/null || true; \
    fi

# Verify that bc files were created
RUN ls -la /work/bc/
