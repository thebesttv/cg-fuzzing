FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract wget --tries=3 --retry-connrefused --waitretry=5 v1.24.5
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/wget/wget-1.24.5.tar.gz && \
    tar -xzf wget-1.24.5.tar.gz && \
    rm wget-1.24.5.tar.gz

WORKDIR /home/SVF-tools/wget-1.24.5

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libssl-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --with-ssl=openssl --disable-nls

# Build wget
--tries=3 --retry-connrefused --waitretry=5 RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/wget --tries=3 --retry-connrefused --waitretry=5 && \
    mv src/wget.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
