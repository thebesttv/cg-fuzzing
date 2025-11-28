FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libexpat 2.7.3
WORKDIR /home/SVF-tools
RUN wget https://github.com/libexpat/libexpat/releases/download/R_2_7_3/expat-2.7.3.tar.gz && \
    tar -xzf expat-2.7.3.tar.gz && \
    rm expat-2.7.3.tar.gz

WORKDIR /home/SVF-tools/expat-2.7.3

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# libexpat uses autotools, configure and make
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build libexpat
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
# xmlwf is the main CLI binary for XML well-formedness checking
RUN mkdir -p ~/bc && \
    extract-bc xmlwf/xmlwf && \
    mv xmlwf/xmlwf.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
