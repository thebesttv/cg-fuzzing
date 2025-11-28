FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract oniguruma 6.9.10
WORKDIR /home/SVF-tools
RUN wget https://github.com/kkos/oniguruma/releases/download/v6.9.10/onig-6.9.10.tar.gz && \
    tar -xzf onig-6.9.10.tar.gz && \
    rm onig-6.9.10.tar.gz

WORKDIR /home/SVF-tools/onig-6.9.10

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure and build with WLLVM (using autotools)
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
# Build the sample test utility (simple) manually with static linking
RUN mkdir -p ~/bc && \
    cd sample && \
    wllvm -g -O0 -I../src -o simple simple.c ../src/.libs/libonig.a -static -Wl,--allow-multiple-definition && \
    extract-bc simple && \
    mv simple.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
