FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract socat v1.7.3.4
WORKDIR /home/SVF-tools
RUN wget http://www.dest-unreach.org/socat/download/socat-1.7.3.4.tar.gz && \
    tar -xzf socat-1.7.3.4.tar.gz && \
    rm socat-1.7.3.4.tar.gz

WORKDIR /home/SVF-tools/socat-1.7.3.4

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure

# Build socat
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc socat && \
    mv socat.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
