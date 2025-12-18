FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract hunspell v1.7.2
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/hunspell/hunspell/releases/download/v1.7.2/hunspell-1.7.2.tar.gz && \
    tar -xzf hunspell-1.7.2.tar.gz && \
    rm hunspell-1.7.2.tar.gz

WORKDIR /home/SVF-tools/hunspell-1.7.2

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -static-libstdc++" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static

# Build hunspell
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from hunspell binary
RUN mkdir -p ~/bc && \
    extract-bc src/tools/hunspell && \
    mv src/tools/hunspell.bc ~/bc/ 2>/dev/null || true

# Verify that bc files were created
RUN ls -la ~/bc/
