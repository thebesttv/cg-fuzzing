FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract Tcl v8.6.15
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://prdownloads.sourceforge.net/tcl/tcl8.6.15-src.tar.gz && \
    tar -xzf tcl8.6.15-src.tar.gz && \
    rm tcl8.6.15-src.tar.gz

WORKDIR /home/SVF-tools/tcl8.6.15/unix

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build Tcl (only tclsh, skip packages due to static linking issues)
RUN make -j$(nproc) tclsh

# Create bc directory and extract bitcode files from tclsh
RUN mkdir -p ~/bc && \
    extract-bc tclsh && \
    mv tclsh.bc ~/bc/ 2>/dev/null || true

# Verify that bc files were created
RUN ls -la ~/bc/
