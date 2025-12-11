FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract groff v1.23.0
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/groff/groff-1.23.0.tar.gz && \
    tar -xzf groff-1.23.0.tar.gz && \
    rm groff-1.23.0.tar.gz

WORKDIR /home/SVF-tools/groff-1.23.0

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file m4 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build groff
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from groff binary
RUN mkdir -p ~/bc && \
    extract-bc groff && \
    mv groff.bc ~/bc/ 2>/dev/null || true

# Verify that bc files were created
RUN ls -la ~/bc/
