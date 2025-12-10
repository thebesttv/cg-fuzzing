FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract gengetopt 2.23
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/gengetopt/gengetopt-2.23.tar.xz && \
    tar -xJf gengetopt-2.23.tar.xz && \
    rm gengetopt-2.23.tar.xz

WORKDIR /home/SVF-tools/gengetopt-2.23

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file texinfo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build gengetopt
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/gengetopt && \
    mv src/gengetopt.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
