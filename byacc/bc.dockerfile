FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract byacc 20240109
WORKDIR /home/SVF-tools
RUN wget https://invisible-mirror.net/archives/byacc/byacc-20240109.tgz && \
    tar -xzf byacc-20240109.tgz && \
    rm byacc-20240109.tgz

WORKDIR /home/SVF-tools/byacc-20240109

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build byacc
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc yacc && \
    mv yacc.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
