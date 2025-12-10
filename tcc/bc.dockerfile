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

# Download and extract TCC (Tiny C Compiler) v0.9.27
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27.tar.bz2 && \
    tar -xjf tcc-0.9.27.tar.bz2 && \
    rm tcc-0.9.27.tar.bz2

WORKDIR /home/SVF-tools/tcc-0.9.27

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
RUN mkdir -p ~/bc && \
    extract-bc tcc && \
    mv tcc.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
