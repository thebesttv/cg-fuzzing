FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract GNU bc 1.08.2
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/bc/bc-1.08.2.tar.gz && \
    tar -xzf bc-1.08.2.tar.gz && \
    rm bc-1.08.2.tar.gz

WORKDIR /home/SVF-tools/bc-1.08.2

# Install build dependencies (file for extract-bc, flex and bison for parser)
RUN apt-get update && \
    apt-get install -y file flex bison ed texinfo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build bc
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc bc/bc && \
    mv bc/bc.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
