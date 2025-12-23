FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract TCC (Tiny C Compiler) v0.9.27

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: tcc" > /work/proj && \
    echo "version: 0.9.27" >> /work/proj && \
    echo "source: https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27.tar.bz2" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27.tar.bz2 && \
    tar -xjf tcc-0.9.27.tar.bz2 && \
    mv tcc-0.9.27 build && \
    rm tcc-0.9.27.tar.bz2

WORKDIR /work/build

# Configure with WLLVM and static linking
# TCC uses a custom configure script (not autotools)
# Disable bcheck (bound checking) as it fails to build on newer glibc
# Use --cc= to specify the compiler
RUN ./configure --prefix=/usr/local --disable-bcheck \
    --cc=wllvm \
    --extra-cflags="-g -O0 -Xclang -disable-llvm-passes" \
    --extra-ldflags="-static -Wl,--allow-multiple-definition"

# Build TCC - just the main binary, not the full install
RUN make tcc -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc tcc && \
    mv tcc.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
