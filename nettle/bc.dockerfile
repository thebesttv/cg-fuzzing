FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract nettle 3.10.2
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/nettle/nettle-3.10.2.tar.gz && \
    tar -xzf nettle-3.10.2.tar.gz && \
    rm nettle-3.10.2.tar.gz

WORKDIR /home/SVF-tools/nettle-3.10.2

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libgmp-dev m4 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Note: nettle needs special handling for static linking
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --disable-openssl --enable-static

# Build nettle
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
# nettle provides: sexp-conv (S-expression converter), nettle-hash (hash computation)
RUN mkdir -p ~/bc && \
    extract-bc tools/sexp-conv && \
    extract-bc tools/nettle-hash && \
    mv tools/sexp-conv.bc ~/bc/ && \
    mv tools/nettle-hash.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
