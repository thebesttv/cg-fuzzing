FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Copy and extract lzip v1.15
WORKDIR /home/SVF-tools
COPY lzip/lzip-1.15.tar.gz /home/SVF-tools/
RUN tar -xzf lzip-1.15.tar.gz && \
    rm lzip-1.15.tar.gz

WORKDIR /home/SVF-tools/lzip-1.15

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure

# Build lzip - override CXX and CXXFLAGS in make command
# lzip's configure doesn't respect CXXFLAGS, so we need to pass them to make
RUN make CXX=wllvm++ CXXFLAGS="-g -O0 -Xclang -disable-llvm-passes" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc lzip && \
    mv lzip.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
