FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tcsh v6.24.16
WORKDIR /home/SVF-tools
RUN wget https://astron.com/pub/tcsh/tcsh-6.24.16.tar.gz && \
    tar -xzf tcsh-6.24.16.tar.gz && \
    rm tcsh-6.24.16.tar.gz

WORKDIR /home/SVF-tools/tcsh-6.24.16

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure

# Build tcsh
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc tcsh && \
    mv tcsh.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
